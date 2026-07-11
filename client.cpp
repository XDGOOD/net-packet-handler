#include <iostream>
#include <string>
#include <vector>
#include <unordered_set>
#include <queue>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

const std::string MAGIC = "AEGS";

// --- Buffer sizing (см. server.cpp) ----------------------------------------
// FIX: та же ошибка, что была на сервере — pbuf/cbuf были ровно BUFFER_SIZE,
// а в них пишется 2-байтовый префикс длины + payload + паддинг + AEAD tag.
// При len близком к максимуму UDP это переполняло буфер.
const size_t BUFFER_SIZE = 65535;
const size_t PAD_MIN = 16;
const size_t PAD_MAX = 128;   // соответствует исходному 16 + rand()%113
const size_t FRAME_HDR = 2;
const size_t TAG_LEN = 16;
const size_t INTERNAL_BUF_SIZE = BUFFER_SIZE + FRAME_HDR + PAD_MAX + TAG_LEN + 64;

const int PBKDF2_ITERATIONS = 200000;

// FIX: kid по-прежнему просто SHA256(token)[0:8] — это публичный
// идентификатор, ему не нужна медленная KDF. А вот сам ключ шифрования
// теперь идёт через PBKDF2 с солью = hex(kid), синхронно с server.cpp,
// иначе они просто перестанут понимать друг друга.
void compute_key_id(const std::string& token, uint8_t* kid_out /*8 bytes*/, std::string& kid_hex_out) {
    SHA256_CTX s; SHA256_Init(&s); SHA256_Update(&s, token.c_str(), token.length());
    uint8_t full[32]; SHA256_Final(full, &s);
    std::memcpy(kid_out, full, 8);
    char hex[17];
    for (int i = 0; i < 8; ++i) sprintf(&hex[i * 2], "%02x", kid_out[i]);
    hex[16] = '\0';
    kid_hex_out = hex;
}

bool derive_key(const std::string& token, const std::string& salt, uint8_t* key_out) {
    return PKCS5_PBKDF2_HMAC(token.c_str(), (int)token.length(),
                              reinterpret_cast<const unsigned char*>(salt.c_str()), (int)salt.length(),
                              PBKDF2_ITERATIONS, EVP_sha256(), 32, key_out) == 1;
}

bool chacha20_poly1305_encrypt(const uint8_t* pt, size_t pt_len, const uint8_t* key, const uint8_t* nonce, uint8_t* ct, size_t& ct_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int len;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int total_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    total_len += len;
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    std::memcpy(ct + total_len, tag, 16);
    ct_len = total_len + 16;
    EVP_CIPHER_CTX_free(ctx); return true;
}

bool chacha20_poly1305_decrypt(const uint8_t* ct, size_t ct_len, const uint8_t* key, const uint8_t* nonce, uint8_t* pt, size_t& pt_len) {
    if (ct_len < 16) return false;
    size_t c_len = ct_len - 16; const uint8_t* tag = ct + c_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx); return false;
    }
    int len;
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)c_len) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int total_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) <= 0) { EVP_CIPHER_CTX_free(ctx); return false; }
    total_len += len;
    pt_len = total_len;
    EVP_CIPHER_CTX_free(ctx); return true;
}

// FIX: простая защита от replay на входящих от сервера пакетах —
// раньше её не было вообще, атакующий мог повторно прогнать перехваченный
// (валидный) зашифрованный пакет и продублировать трафик в локальный wg-core.
class NonceCache {
    std::unordered_set<std::string> cache;
    std::queue<std::string> history;
public:
    bool seen_or_add(const uint8_t* n) {
        std::string s((const char*)n, 12);
        if (cache.count(s)) return true;
        cache.insert(s); history.push(s);
        if (cache.size() > 1000) { cache.erase(history.front()); history.pop(); }
        return false;
    }
};

size_t secure_pad_len() {
    uint8_t b; RAND_bytes(&b, 1);
    return PAD_MIN + (b % (PAD_MAX - PAD_MIN + 1));
}

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0 << " --server <host> --token <token> [--port <local_port>]\n";
}

int main(int argc, char* argv[]) {
    std::string s_host, token;
    int l_port = 51821;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--server") && i + 1 < argc) s_host = argv[++i];
        else if (!strcmp(argv[i], "--token") && i + 1 < argc) token = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) l_port = atoi(argv[++i]);
        else { usage(argv[0]); return 1; }
    }
    if (s_host.empty() || token.empty()) { usage(argv[0]); return 1; }

    uint8_t raw_kid[8];
    std::string kid_hex;
    compute_key_id(token, raw_kid, kid_hex);

    uint8_t key[32];
    if (!derive_key(token, kid_hex, key)) {
        std::cerr << "key derivation failed\n";
        return 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_in l_addr {};
    l_addr.sin_family = AF_INET; l_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); l_addr.sin_port = htons(l_port);
    if (bind(fd, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) { perror("bind"); return 1; }

    // FIX: gethostbyname устарел/не потокобезопасен -> getaddrinfo, как на сервере.
    struct sockaddr_in s_addr {};
    s_addr.sin_family = AF_INET; s_addr.sin_port = htons(50001);
    {
        struct addrinfo hints {}, *res = nullptr;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(s_host.c_str(), nullptr, &hints, &res) == 0 && res) {
            s_addr.sin_addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
            freeaddrinfo(res);
        } else if (inet_pton(AF_INET, s_host.c_str(), &s_addr.sin_addr) != 1) {
            std::cerr << "failed to resolve " << s_host << "\n";
            return 1;
        }
    }

    struct sockaddr_in wg_addr {}; bool has_wg = false;
    NonceCache seen_nonces;

    // FIX: внутренние буферы с запасом, см. INTERNAL_BUF_SIZE выше.
    std::vector<uint8_t> buf(BUFFER_SIZE);
    std::vector<uint8_t> pbuf(INTERNAL_BUF_SIZE);
    std::vector<uint8_t> cbuf(INTERNAL_BUF_SIZE);

    while (true) {
        struct sockaddr_in src; socklen_t slen = sizeof(src);
        ssize_t len = recvfrom(fd, buf.data(), buf.size(), 0, (struct sockaddr*)&src, &slen);
        if (len <= 0) continue;

        if (src.sin_addr.s_addr == s_addr.sin_addr.s_addr && src.sin_port == s_addr.sin_port) {
            // пакет от aegis-сервера -> расшифровать и отдать локальному wg-core
            if (len < 24 || std::memcmp(buf.data(), MAGIC.data(), 4) != 0) continue;
            const uint8_t* nonce = buf.data() + 12;
            if (seen_nonces.seen_or_add(nonce)) continue;

            size_t dlen = 0;
            if (chacha20_poly1305_decrypt(buf.data() + 24, len - 24, key, nonce, pbuf.data(), dlen)) {
                if (dlen < 2) continue;
                uint16_t plen = (pbuf[0] << 8) | pbuf[1];
                if (has_wg && plen <= dlen - 2) sendto(fd, pbuf.data() + 2, plen, 0, (struct sockaddr*)&wg_addr, sizeof(wg_addr));
            }
        } else {
            // пакет от локального wg-core -> зашифровать и отправить на сервер
            wg_addr = src; has_wg = true;

            size_t pad_len = secure_pad_len();
            size_t frame_len = FRAME_HDR + (size_t)len + pad_len;
            if (frame_len + TAG_LEN > pbuf.size()) { pad_len = 0; frame_len = FRAME_HDR + (size_t)len; }

            uint16_t plen_be = htons((uint16_t)len);
            std::memcpy(pbuf.data(), &plen_be, 2);
            std::memcpy(pbuf.data() + 2, buf.data(), len);
            if (pad_len > 0) RAND_bytes(pbuf.data() + 2 + len, (int)pad_len);

            uint8_t nonce[12]; RAND_bytes(nonce, 12);
            size_t elen = 0;
            if (chacha20_poly1305_encrypt(pbuf.data(), frame_len, key, nonce, cbuf.data(), elen)) {
                std::vector<uint8_t> out; out.reserve(24 + elen);
                out.insert(out.end(), MAGIC.begin(), MAGIC.end());
                out.insert(out.end(), raw_kid, raw_kid + 8);
                out.insert(out.end(), nonce, nonce + 12);
                out.insert(out.end(), cbuf.begin(), cbuf.begin() + elen);
                sendto(fd, out.data(), out.size(), 0, (struct sockaddr*)&s_addr, sizeof(s_addr));
            }
        }
    }
}
