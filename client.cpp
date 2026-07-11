#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

const std::string MAGIC = "AEGS";
const int BUFFER_SIZE = 65535;

void derive_key(const std::string& token, uint8_t* key) {
    SHA256_CTX sha256; SHA256_Init(&sha256); SHA256_Update(&sha256, token.c_str(), token.length()); SHA256_Final(key, &sha256);
}

bool chacha20_poly1305_encrypt(const uint8_t* pt, size_t pt_len, const uint8_t* key, const uint8_t* nonce, uint8_t* ct, size_t& ct_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 || EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) return false;
    int len, total_len;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, pt_len) != 1) return false;
    total_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) return false;
    total_len += len;
    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) return false;
    std::memcpy(ct + total_len, tag, 16); ct_len = total_len + 16;
    EVP_CIPHER_CTX_free(ctx); return true;
}

bool chacha20_poly1305_decrypt(const uint8_t* ct, size_t ct_len, const uint8_t* key, const uint8_t* nonce, uint8_t* pt, size_t& pt_len) {
    if (ct_len < 16) return false;
    size_t c_len = ct_len - 16; const uint8_t* tag = ct + c_len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx || EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1 || EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) return false;
    int len, total_len;
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, c_len) != 1) return false;
    total_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag);
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) <= 0) return false;
    pt_len = total_len + len;
    EVP_CIPHER_CTX_free(ctx); return true;
}

int main(int argc, char* argv[]) {
    std::string s_host, token; int l_port = 51821;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--server")) s_host = argv[++i];
        else if (!strcmp(argv[i], "--token")) token = argv[++i];
        else if (!strcmp(argv[i], "--port")) l_port = atoi(argv[++i]);
    }
    if (s_host.empty() || token.empty()) return 1;

    uint8_t key[32]; derive_key(token, key);
    uint8_t raw_kid[8];
    SHA256_CTX s; SHA256_Init(&s); SHA256_Update(&s, token.c_str(), token.length());
    uint8_t th[32]; SHA256_Final(th, &s); std::memcpy(raw_kid, th, 8);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in l_addr{}; l_addr.sin_family = AF_INET; l_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); l_addr.sin_port = htons(l_port);
    bind(fd, (struct sockaddr*)&l_addr, sizeof(l_addr));

    struct sockaddr_in s_addr{}; s_addr.sin_family = AF_INET; s_addr.sin_port = htons(50001);
    struct hostent* hp = gethostbyname(s_host.c_str());
    if (hp) std::memcpy(&s_addr.sin_addr.s_addr, hp->h_addr_list[0], hp->h_length);
    else inet_pton(AF_INET, s_host.c_str(), &s_addr.sin_addr);

    struct sockaddr_in wg_addr{}; bool has_wg = false;
    uint8_t buf[BUFFER_SIZE], pbuf[BUFFER_SIZE], cbuf[BUFFER_SIZE];

    while (true) {
        struct sockaddr_in src; socklen_t slen = sizeof(src);
        ssize_t len = recvfrom(fd, buf, BUFFER_SIZE, 0, (struct sockaddr*)&src, &slen);
        if (len <= 0) continue;

        if (src.sin_addr.s_addr == s_addr.sin_addr.s_addr && src.sin_port == s_addr.sin_port) {
            if (len < 24 || std::memcmp(buf, MAGIC.data(), 4) != 0) continue;
            size_t dlen = 0;
            if (chacha20_poly1305_decrypt(buf + 24, len - 24, key, buf + 12, pbuf, dlen)) {
                uint16_t plen = (pbuf[0] << 8) | pbuf[1];
                if (has_wg && plen <= dlen - 2) sendto(fd, pbuf + 2, plen, 0, (struct sockaddr*)&wg_addr, sizeof(wg_addr));
            }
        } else {
            wg_addr = src; has_wg = true;
            uint16_t plen = htons((uint16_t)len);
            std::memcpy(pbuf, &plen, 2); std::memcpy(pbuf + 2, buf, len);
            size_t pad_len = 16 + (std::rand() % 113); RAND_bytes(pbuf + 2 + len, pad_len);
            
            uint8_t nonce[12]; RAND_bytes(nonce, 12);
            size_t elen = 0;
            if (chacha20_poly1305_encrypt(pbuf, 2 + len + pad_len, key, nonce, cbuf, elen)) {
                std::vector<uint8_t> out; out.reserve(24 + elen);
                out.insert(out.end(), MAGIC.begin(), MAGIC.end());
                out.insert(out.end(), raw_kid, raw_kid + 8);
                out.insert(out.end(), nonce, nonce + 12);
                out.insert(out.end(), cbuf, cbuf + elen);
                sendto(fd, out.data(), out.size(), 0, (struct sockaddr*)&s_addr, sizeof(s_addr));
            }
        }
    }
}
