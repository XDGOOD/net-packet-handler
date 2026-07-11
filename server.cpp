#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <chrono>
#include <thread>

const std::string MAGIC = "AEGS";
const std::string WG_HOST = "wg-core";
const int WG_PORT = 51820;
const std::string DB_PATH = "/app/data/aegis.db";
const int MAX_EVENTS = 1024;

// --- Buffer sizing -------------------------------------------------------
// FIX: старые dec_buf/enc_buf были ровно BUFFER_SIZE, но в них пишется
// заголовок длины (2 байта) + payload + рандомный паддинг (до PAD_MAX) +
// AEAD tag (16 байт). При payload, близком к максимуму UDP-датаграммы,
// это переполняло буфер. Теперь внутренние буферы больше исходного,
// с явным запасом.
const size_t BUFFER_SIZE = 65535;          // сырой recv-буфер (совпадает с макс. UDP payload)
const size_t PAD_MIN = 32;
const size_t PAD_MAX = 256;                 // верхняя граница паддинга (32 + rand()%225 -> макс 256)
const size_t FRAME_HDR = 2;                 // 2-байтовый префикс длины
const size_t TAG_LEN = 16;                  // ChaCha20-Poly1305 tag
const size_t INTERNAL_BUF_SIZE = BUFFER_SIZE + FRAME_HDR + PAD_MAX + TAG_LEN + 64; // +запас

const int PBKDF2_ITERATIONS = 200000;

// --- KDF -------------------------------------------------------------------
// FIX: раньше ключ был просто SHA256(token) без соли и без замедления —
// это не KDF, а просто хэш, что делает офлайн-брутфорс токена тривиальным
// при недостаточной энтропии. Теперь PBKDF2-HMAC-SHA256 с солью = key_id
// (соль хотя бы уникальна на пользователя, хоть и не случайна — в идеале
// в схему БД стоит добавить отдельную колонку со случайной солью).
bool derive_key(const std::string& token, const std::string& salt, uint8_t* key_out) {
    return PKCS5_PBKDF2_HMAC(token.c_str(), (int)token.length(),
                              reinterpret_cast<const unsigned char*>(salt.c_str()), (int)salt.length(),
                              PBKDF2_ITERATIONS, EVP_sha256(), 32, key_out) == 1;
}

bool chacha20_poly1305_encrypt(const uint8_t* plaintext, size_t plaintext_len, const uint8_t* key, const uint8_t* nonce, uint8_t* ciphertext, size_t& ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int total_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    total_len += len;
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    std::memcpy(ciphertext + total_len, tag, 16);
    ciphertext_len = total_len + 16;
    EVP_CIPHER_CTX_free(ctx); return true;
}

bool chacha20_poly1305_decrypt(const uint8_t* ciphertext, size_t ciphertext_total_len, const uint8_t* key, const uint8_t* nonce, uint8_t* plaintext, size_t& plaintext_len) {
    if (ciphertext_total_len < 16) return false;
    size_t c_len = ciphertext_total_len - 16;
    const uint8_t* tag = ciphertext + c_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)c_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int total_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    total_len += len;
    plaintext_len = total_len;
    EVP_CIPHER_CTX_free(ctx); return true;
}

struct Session {
    std::string key_id_hex;
    uint8_t key[32];
    struct sockaddr_in client_addr {};
    bool has_client = false;
    int wg_fd = -1;
    std::unordered_set<std::string> nonce_cache;
    std::queue<std::string> nonce_history;

    void add_nonce(const uint8_t* n_bytes) {
        std::string n((char*)n_bytes, 12);
        nonce_cache.insert(n); nonce_history.push(n);
        if (nonce_cache.size() > 1000) { nonce_cache.erase(nonce_history.front()); nonce_history.pop(); }
    }
    bool check_nonce(const uint8_t* n_bytes) {
        return nonce_cache.count(std::string((char*)n_bytes, 12)) != 0;
    }
};

// Сессии живут всё время работы процесса (по одной на пользователя из БД),
// поэтому new без delete тут осознанно, не утечка в привычном смысле.
std::unordered_map<std::string, Session*> sessions;
std::unordered_map<int, Session*> fd_to_session;

struct FailRecord { double weight = 0; double last_seen = 0; int level = 0; };
std::unordered_map<std::string, FailRecord> failed_attempts;
std::unordered_map<std::string, double> banned_ips;
const int ban_levels[] = {0, 30, 300, 3600};

// FIX: обе карты раньше росли бесконечно (никогда не чистились) — это
// вектор DoS по памяти (спам невалидными пакетами с разных IP).
// Теперь периодически подчищаем протухшие записи.
double last_cleanup = 0;
const double CLEANUP_INTERVAL = 60.0;
const double FAIL_IDLE_TTL = 600.0;

void cleanup_maps(double now) {
    if (now - last_cleanup < CLEANUP_INTERVAL) return;
    last_cleanup = now;

    for (auto it = banned_ips.begin(); it != banned_ips.end(); ) {
        if (now > it->second) it = banned_ips.erase(it); else ++it;
    }
    for (auto it = failed_attempts.begin(); it != failed_attempts.end(); ) {
        if (now - it->second.last_seen > FAIL_IDLE_TTL) it = failed_attempts.erase(it); else ++it;
    }
}

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

void record_fail(const std::string& ip, double now, double weight) {
    auto& rec = failed_attempts[ip];
    if (rec.level == 0) rec.level = 1;
    if (now - rec.last_seen > 120.0) { rec.weight = 0; }
    rec.last_seen = now;
    rec.weight += weight;
    if (rec.weight >= 10.0) {
        int lvl = std::min(rec.level, 3);
        banned_ips[ip] = now + ban_levels[lvl];
        rec.weight = 0; rec.level = lvl + 1;
    }
}

// FIX: секьюрный рандом вместо rand()%N для длины паддинга —
// rand() без srand() выдаёт детерминированную последовательность,
// что немного облегчает fingerprinting как раз того трафика,
// который паддинг должен маскировать.
size_t secure_pad_len() {
    uint8_t b;
    RAND_bytes(&b, 1);
    return PAD_MIN + (b % (PAD_MAX - PAD_MIN + 1));
}

int main() {
    sqlite3* db;
    if (sqlite3_open(DB_PATH.c_str(), &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT aegis_key_id, aegis_token FROM users", -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Session* s = new Session();
                s->key_id_hex = (const char*)sqlite3_column_text(stmt, 0);
                std::string token = (const char*)sqlite3_column_text(stmt, 1);
                if (!derive_key(token, s->key_id_hex, s->key)) {
                    std::cerr << "key derivation failed for " << s->key_id_hex << "\n";
                    delete s;
                    continue;
                }
                sessions[s->key_id_hex] = s;
            }
            sqlite3_finalize(stmt);
        } else {
            std::cerr << "failed to prepare user query: " << sqlite3_errmsg(db) << "\n";
        }
        sqlite3_close(db);
    } else {
        std::cerr << "failed to open db at " << DB_PATH << ": " << sqlite3_errmsg(db) << "\n";
        return 1;
    }

    if (sessions.empty()) {
        std::cerr << "no sessions loaded from db, nothing to serve\n";
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    if (!set_nonblocking(server_fd)) { perror("fcntl"); return 1; }

    struct sockaddr_in saddr {};
    saddr.sin_family = AF_INET; saddr.sin_addr.s_addr = INADDR_ANY; saddr.sin_port = htons(50001);
    if (bind(server_fd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) { perror("bind"); return 1; }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev {}, events[MAX_EVENTS];
    ev.events = EPOLLIN; ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    // FIX: gethostbyname устарел и не потокобезопасен — заменили на getaddrinfo.
    struct sockaddr_in wg_addr {};
    wg_addr.sin_family = AF_INET; wg_addr.sin_port = htons(WG_PORT);
    {
        struct addrinfo hints {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(WG_HOST.c_str(), nullptr, &hints, &res) == 0 && res) {
            wg_addr.sin_addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
            freeaddrinfo(res);
        } else {
            std::cerr << "failed to resolve " << WG_HOST << ", falling back to 127.0.0.1\n";
            inet_pton(AF_INET, "127.0.0.1", &wg_addr.sin_addr);
        }
    }

    // FIX: буферы под расшифрованный/зашифрованный кадр теперь больше
    // сырого recv-буфера, с запасом под заголовок+паддинг+tag (см. INTERNAL_BUF_SIZE).
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    std::vector<uint8_t> dec_buf(INTERNAL_BUF_SIZE);
    std::vector<uint8_t> enc_buf(INTERNAL_BUF_SIZE);

    while (true) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
        cleanup_maps(now);

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;

            if (fd == server_fd) {
                struct sockaddr_in caddr; socklen_t clen = sizeof(caddr);
                ssize_t len = recvfrom(fd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&caddr, &clen);
                if (len < 0) continue;

                std::string ip = inet_ntoa(caddr.sin_addr);
                auto ban_it = banned_ips.find(ip);
                if (ban_it != banned_ips.end() && now < ban_it->second) continue;

                if (len < 24 || std::memcmp(buffer.data(), MAGIC.data(), 4) != 0) { record_fail(ip, now, 1.0); continue; }

                char kid[17];
                for (int j = 0; j < 8; ++j) sprintf(&kid[j * 2], "%02x", buffer[4 + j]);
                kid[16] = '\0';

                auto sess_it = sessions.find(kid);
                if (sess_it == sessions.end()) { record_fail(ip, now, 0.5); continue; }
                Session* s = sess_it->second; s->client_addr = caddr; s->has_client = true;

                const uint8_t* nonce = buffer.data() + 12;
                if (s->check_nonce(nonce)) continue;

                size_t dec_len = 0;
                if (!chacha20_poly1305_decrypt(buffer.data() + 24, len - 24, s->key, nonce, dec_buf.data(), dec_len)) {
                    record_fail(ip, now, 0.1); continue;
                }

                failed_attempts.erase(ip); s->add_nonce(nonce);

                if (s->wg_fd == -1) {
                    s->wg_fd = socket(AF_INET, SOCK_DGRAM, 0);
                    if (s->wg_fd < 0 || !set_nonblocking(s->wg_fd)) { perror("wg socket"); continue; }
                    struct epoll_event wev {}; wev.events = EPOLLIN; wev.data.fd = s->wg_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->wg_fd, &wev);
                    fd_to_session[s->wg_fd] = s;
                }

                if (dec_len < 2) continue;
                uint16_t plen = (dec_buf[0] << 8) | dec_buf[1];
                if (plen <= dec_len - 2) sendto(s->wg_fd, dec_buf.data() + 2, plen, 0, (struct sockaddr*)&wg_addr, sizeof(wg_addr));

            } else {
                auto fs_it = fd_to_session.find(fd);
                if (fs_it == fd_to_session.end()) continue;
                Session* s = fs_it->second;

                ssize_t len = recv(fd, buffer.data(), buffer.size(), 0);
                if (len <= 0) continue;

                std::this_thread::sleep_for(std::chrono::milliseconds(1 + std::rand() % 3));

                size_t pad_len = secure_pad_len();
                // на всякий случай не вылезаем за внутренний буфер даже с запасом
                size_t frame_len = FRAME_HDR + (size_t)len + pad_len;
                if (frame_len + TAG_LEN > dec_buf.size()) { pad_len = 0; frame_len = FRAME_HDR + (size_t)len; }

                uint16_t plen_be = htons((uint16_t)len);
                std::memcpy(dec_buf.data(), &plen_be, 2);
                std::memcpy(dec_buf.data() + 2, buffer.data(), len);
                if (pad_len > 0) RAND_bytes(dec_buf.data() + 2 + len, (int)pad_len);

                uint8_t nonce[12]; RAND_bytes(nonce, 12);
                size_t enc_len = 0;
                if (chacha20_poly1305_encrypt(dec_buf.data(), frame_len, s->key, nonce, enc_buf.data(), enc_len) && s->has_client) {
                    std::vector<uint8_t> out; out.reserve(24 + enc_len);
                    out.insert(out.end(), MAGIC.begin(), MAGIC.end());
                    for (int k = 0; k < 8; ++k) {
                        unsigned int b; std::sscanf(s->key_id_hex.c_str() + (k * 2), "%02x", &b);
                        out.push_back((uint8_t)b);
                    }
                    out.insert(out.end(), nonce, nonce + 12);
                    out.insert(out.end(), enc_buf.begin(), enc_buf.begin() + enc_len);
                    sendto(server_fd, out.data(), out.size(), 0, (struct sockaddr*)&s->client_addr, sizeof(s->client_addr));
                }
            }
        }
    }
}
