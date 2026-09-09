#include "chaff_engine.h"
#include <random>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>
#include <arpa/inet.h>
#include <iostream>

// Use the function from client.cpp for masking
extern bool mask_unmask_header(const uint8_t* in, size_t len, const uint8_t* mask_key, const uint8_t* hdr_iv, uint8_t* out);
extern bool chacha20_poly1305_encrypt(const uint8_t* pt, size_t pt_len, const uint8_t* key, const uint8_t* nonce, uint8_t* ct, size_t& ct_len);
static const std::string CHAFF_VER_MAGIC = "AG2\x01";

ChaffEngine::ChaffEngine(int idle_threshold_ms, int min_interval_ms, int max_interval_ms)
    : idle_threshold_ms_(idle_threshold_ms), min_interval_ms_(min_interval_ms), max_interval_ms_(max_interval_ms) {
    mark_real_packet();
}

void ChaffEngine::schedule_next_chaff() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(min_interval_ms_, max_interval_ms_);
    next_chaff_time_ = std::chrono::steady_clock::now() + std::chrono::milliseconds(dist(gen));
}

void ChaffEngine::mark_real_packet() {
    last_real_packet_ = std::chrono::steady_clock::now();
    schedule_next_chaff();
}

bool ChaffEngine::should_send_chaff() {
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_real_packet_).count() > idle_threshold_ms_) {
        if (now >= next_chaff_time_) {
            schedule_next_chaff();
            return true;
        }
    }
    return false;
}

std::vector<uint8_t> ChaffEngine::build_chaff_packet(const uint8_t* raw_kid, const uint8_t* mask_key, const uint8_t* send_key, uint64_t& tx_seq) {
    // Generate chaff payload (2 bytes zero len + padding)
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> pad_dist(64, 128);
    int pad_len = pad_dist(gen);
    
    std::vector<uint8_t> pbuf(2 + pad_len, 0); 
    RAND_bytes(pbuf.data() + 2, pad_len);
    
    // Encrypt
    uint8_t aead_nonce[12] = {0};
    tx_seq++;
    std::memcpy(aead_nonce, &tx_seq, sizeof(uint64_t));
    RAND_bytes(aead_nonce + 8, 4);

    std::vector<uint8_t> cbuf(pbuf.size() + 16);
    size_t elen = 0;
    if (!chacha20_poly1305_encrypt(pbuf.data(), pbuf.size(), send_key, aead_nonce, cbuf.data(), elen)) {
        return {};
    }

    uint16_t junk_len = 0; // No junk for simplicity

    uint8_t hdr_plain[16];
    std::memcpy(hdr_plain, raw_kid, 8);
    hdr_plain[8] = (junk_len >> 8) & 0xFF;
    hdr_plain[9] = junk_len & 0xFF;
    hdr_plain[10] = 0x80; // CHAFF flag
    hdr_plain[11] = 0;
    std::memcpy(hdr_plain + 12, CHAFF_VER_MAGIC.data(), 4);

    uint8_t hdr_iv[12]; RAND_bytes(hdr_iv, 12);
    uint8_t masked_hdr[16];
    if (!mask_unmask_header(hdr_plain, 16, mask_key, hdr_iv, masked_hdr)) {
        return {};
    }

    std::vector<uint8_t> out_buf;
    out_buf.reserve(12 + 16 + junk_len + 12 + elen);
    out_buf.insert(out_buf.end(), hdr_iv, hdr_iv + 12);
    out_buf.insert(out_buf.end(), masked_hdr, masked_hdr + 16);
    out_buf.insert(out_buf.end(), aead_nonce, aead_nonce + 12);
    out_buf.insert(out_buf.end(), cbuf.data(), cbuf.data() + elen);
    
    return out_buf;
}
