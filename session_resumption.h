#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Session Resumption Token Manager
// Allows reconnect in <5ms instead of ~1s PBKDF2 handshake
// Token: 96 bytes = nonce(32) + ciphertext(32) + tag(16) + padding(16)
// Encrypted with ChaCha20-Poly1305, keyed from HKDF(MasterKey,"aegs-v4-resumption-key")
// ==============================================================================
#pragma once
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_set>
#include <string>
#include <chrono>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

// 96 bytes on wire (sent in HANDSHAKE_RESP extension)
struct ResumptionToken {
    uint8_t nonce[32];      // random nonce
    uint8_t ciphertext[32]; // encrypted payload: session_id(8)+ip(4)+expiry_ms(8)+zeros(12)
    uint8_t tag[16];        // Poly1305 AEAD tag
    uint8_t reserved[16];   // zero-padded, future use
}; // total: 96 bytes
static_assert(sizeof(ResumptionToken) == 96, "ResumptionToken size mismatch");

class ResumptionManager {
public:
    ResumptionManager() = default;

    // Issue a resumption token after successful handshake
    // Returns false if crypto fails
    bool issue(uint64_t session_id, uint32_t assigned_ip,
               const uint8_t master_key[32], ResumptionToken& tok_out) {
        // Derive resumption key from master key
        uint8_t rkey[32];
        if (!derive_resumption_key(master_key, rkey)) return false;

        // Generate random nonce
        if (RAND_bytes(tok_out.nonce, 32) != 1) return false;

        // Build plaintext: session_id(8) + ip(4) + expiry_ms(8) + zeros(12)
        uint8_t plain[32] = {0};
        memcpy(plain, &session_id, 8);
        memcpy(plain + 8, &assigned_ip, 4);
        uint64_t expiry = now_ms() + 180000ULL; // 3 minutes
        memcpy(plain + 12, &expiry, 8);

        // Encrypt with ChaCha20-Poly1305
        // nonce for AEAD = first 12 bytes of token nonce
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        int outlen = 0, flen = 0;
        bool ok = (
            EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
            EVP_EncryptInit_ex(ctx, NULL, NULL, rkey, tok_out.nonce) == 1 &&
            EVP_EncryptUpdate(ctx, tok_out.ciphertext, &outlen, plain, 32) == 1 &&
            EVP_EncryptFinal_ex(ctx, tok_out.ciphertext + outlen, &flen) == 1
        );
        if (ok) {
            uint8_t tag[16];
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
            if (ok) memcpy(tok_out.tag, tag, 16);
        }
        EVP_CIPHER_CTX_free(ctx);
        memset(tok_out.reserved, 0, 16);
        return ok;
    }

    // Verify and decode a token
    // Returns false if: expired, already used, AEAD fails, or crypto error
    bool verify(const ResumptionToken& tok, const uint8_t master_key[32],
                uint64_t& session_id_out, uint32_t& ip_out) {
        uint8_t rkey[32];
        if (!derive_resumption_key(master_key, rkey)) return false;

        // Anti-replay: check nonce not seen before
        std::string nonce_key(reinterpret_cast<const char*>(tok.nonce), 32);
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (used_nonces_.count(nonce_key)) return false;
        }

        // Decrypt
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        uint8_t plain[32];
        int outlen = 0, flen = 0;
        uint8_t tag_copy[16];
        memcpy(tag_copy, tok.tag, 16);
        bool ok = (
            EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
            EVP_DecryptInit_ex(ctx, NULL, NULL, rkey, tok.nonce) == 1 &&
            EVP_DecryptUpdate(ctx, plain, &outlen, tok.ciphertext, 32) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag_copy) == 1 &&
            EVP_DecryptFinal_ex(ctx, plain + outlen, &flen) > 0
        );
        EVP_CIPHER_CTX_free(ctx);
        if (!ok) return false;

        // Check expiry
        uint64_t expiry = 0;
        memcpy(&expiry, plain + 12, 8);
        if (now_ms() > expiry) return false;

        // Mark nonce as used (anti-replay)
        {
            std::lock_guard<std::mutex> lk(mu_);
            used_nonces_.insert(nonce_key);
            // Prune old nonces every 10000 entries
            if (used_nonces_.size() > 10000) used_nonces_.clear();
        }

        memcpy(&session_id_out, plain, 8);
        memcpy(&ip_out, plain + 8, 4);
        return true;
    }

private:
    std::mutex mu_;
    std::unordered_set<std::string> used_nonces_;

    static uint64_t now_ms() {
        return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    static bool derive_resumption_key(const uint8_t master_key[32], uint8_t out[32]) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
        if (!ctx) return false;
        static const unsigned char info[] = "aegs-v4-resumption-key";
        static const unsigned char salt[] = "aegis-v2-salt";
        size_t olen = 32;
        bool ok = (
            EVP_PKEY_derive_init(ctx) > 0 &&
            EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)-1) > 0 &&
            EVP_PKEY_CTX_set1_hkdf_key(ctx, master_key, 32) > 0 &&
            EVP_PKEY_CTX_add1_hkdf_info(ctx, info, sizeof(info)-1) > 0 &&
            EVP_PKEY_derive(ctx, out, &olen) > 0
        );
        EVP_PKEY_CTX_free(ctx);
        return ok;
    }
};
