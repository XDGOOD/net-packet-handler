#include <iostream>
#include <string>
#include <vector>
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
const int BUFFER_SIZE = 65535;

void derive_key(const std::string& token, uint8_t* key) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, token.c_str(), token.length());
    SHA256_Final(key, &sha256);
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
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
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
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, c_len) != 1) {
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
    struct sockaddr_in client_addr;
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
        return nonce_cache.count(std::string((char*)n_bytes, 12));
    }
};

std::unordered_map<std::string, Session*> sessions;
std::unordered_map<int, Session*> fd_to_session;
std::unordered_map<std::string, struct { double weight; double last_seen; int level; }> failed_attempts;
std::unordered_map<std::string, double> banned_ips;
const int ban_levels[] = {0, 30, 300, 3600};

void set_nonblocking(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK); }

void record_fail(const std::string& ip, double now, double weight) {
    auto& rec = failed_attempts[ip];
    if (rec.level == 0) rec.level = 1;
    if (now - rec.last_seen > 120.0) { rec.weight = 0; rec.last_seen = now; }
    rec.weight += weight;
    if (rec.weight >= 10.0) {
        int lvl = std::min(rec.level, 3);
        banned_ips[ip] = now + ban_levels[lvl];
        rec.weight = 0; rec.last_seen = now; rec.level = lvl + 1;
    }
}

int main() {
    sqlite3* db;
    if (sqlite3_open(DB_PATH.c_str(), &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, "SELECT aegis_key_id, aegis_token FROM users", -1, &stmt, NULL) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Session* s = new Session();
                s->key_id_hex = (const char*)sqlite3_column_text(stmt, 0);
                derive_key((const char*)sqlite3_column_text(stmt, 1), s->key);
                sessions[s->key_id_hex] = s;
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    
    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    set_nonblocking(server_fd);
    struct sockaddr_in saddr{}; saddr.sin_family = AF_INET; saddr.sin_addr.s_addr = INADDR_ANY; saddr.sin_port = htons(50001);
    bind(server_fd, (struct sockaddr*)&saddr, sizeof(saddr));

    int epoll_fd = epoll_create1(0);
    struct epoll_event ev{}, events[MAX_EVENTS];
    ev.events = EPOLLIN; ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

    struct sockaddr_in wg_addr{}; wg_addr.sin_family = AF_INET; wg_addr.sin_port = htons(WG_PORT);
    struct hostent* hp = gethostbyname(WG_HOST.c_str());
    if (hp) std::memcpy(&wg_addr.sin_addr.s_addr, hp->h_addr_list[0], hp->h_length);
    else inet_pton(AF_INET, "127.0.0.1", &wg_addr.sin_addr);

    uint8_t buffer[BUFFER_SIZE], dec_buf[BUFFER_SIZE], enc_buf[BUFFER_SIZE];

    while (true) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            if (fd == server_fd) {
                struct sockaddr_in caddr; socklen_t clen = sizeof(caddr);
                ssize_t len = recvfrom(fd, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&caddr, &clen);
                if (len < 0) continue;
                std::string ip = inet_ntoa(caddr.sin_addr);
                if (banned_ips.count(ip) && now < banned_ips[ip]) continue;

                if (len < 24 || std::memcmp(buffer, MAGIC.data(), 4) != 0) { record_fail(ip, now, 1.0); continue; }
                
                char kid[17];
                for(int j=0; j<8; ++j) sprintf(&kid[j*2], "%02x", buffer[4+j]);
                if (!sessions.count(kid)) { record_fail(ip, now, 0.5); continue; }
                
                Session* s = sessions[kid]; s->client_addr = caddr; s->has_client = true;
                const uint8_t* nonce = buffer + 12;
                if (s->check_nonce(nonce)) continue;
                
                size_t dec_len = 0;
                if (!chacha20_poly1305_decrypt(buffer + 24, len - 24, s->key, nonce, dec_buf, dec_len)) {
                    record_fail(ip, now, 0.1); continue;
                }
                failed_attempts.erase(ip); s->add_nonce(nonce);
                
                if (s->wg_fd == -1) {
                    s->wg_fd = socket(AF_INET, SOCK_DGRAM, 0); set_nonblocking(s->wg_fd);
                    struct epoll_event wev{}; wev.events = EPOLLIN; wev.data.fd = s->wg_fd;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, s->wg_fd, &wev);
                    fd_to_session[s->wg_fd] = s;
                }
                uint16_t plen = (dec_buf[0] << 8) | dec_buf[1];
                if (plen <= dec_len - 2) sendto(s->wg_fd, dec_buf + 2, plen, 0, (struct sockaddr*)&wg_addr, sizeof(wg_addr));
            } else {
                Session* s = fd_to_session[fd];
                ssize_t len = recv(fd, buffer, BUFFER_SIZE, 0);
                if (len <= 0) continue;
                std::this_thread::sleep_for(std::chrono::milliseconds(1 + std::rand() % 3));
                
                uint16_t plen = htons((uint16_t)len);
                std::memcpy(dec_buf, &plen, 2); std::memcpy(dec_buf + 2, buffer, len);
                size_t pad_len = 32 + (std::rand() % 225);
                RAND_bytes(dec_buf + 2 + len, pad_len);
                
                uint8_t nonce[12]; RAND_bytes(nonce, 12);
                size_t enc_len = 0;
                if (chacha20_poly1305_encrypt(dec_buf, 2 + len + pad_len, s->key, nonce, enc_buf, enc_len) && s->has_client) {
                    std::vector<uint8_t> out; out.reserve(24 + enc_len);
                    out.insert(out.end(), MAGIC.begin(), MAGIC.end());
                    for (int k = 0; k < 8; ++k) {
                        unsigned int b; std::sscanf(s->key_id_hex.c_str() + (k * 2), "%02x", &b);
                        out.push_back((uint8_t)b);
                    }
                    out.insert(out.end(), nonce, nonce + 12);
                    out.insert(out.end(), enc_buf, enc_buf + enc_len);
                    sendto(server_fd, out.data(), out.size(), 0, (struct sockaddr*)&s->client_addr, sizeof(s->client_addr));
                }
            }
        }
    }
}
