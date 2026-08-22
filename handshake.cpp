#include "handshake.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <cstring>
#include <chrono>
#include <fstream>
#include <stdexcept>
#include <iostream>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

// Helpers
static uint64_t htobe64_compat(uint64_t host_64) {
    uint64_t res;
    uint8_t* p = (uint8_t*)&res;
    p[0] = (uint8_t)(host_64 >> 56);
    p[1] = (uint8_t)(host_64 >> 48);
    p[2] = (uint8_t)(host_64 >> 40);
    p[3] = (uint8_t)(host_64 >> 32);
    p[4] = (uint8_t)(host_64 >> 24);
    p[5] = (uint8_t)(host_64 >> 16);
    p[6] = (uint8_t)(host_64 >> 8);
    p[7] = (uint8_t)(host_64);
    return res;
}

static uint64_t be64toh_compat(uint64_t big_endian_64) {
    const uint8_t* p = (const uint8_t*)&big_endian_64;
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static EVP_PKEY* generate_x25519() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY* pkey = NULL;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static std::vector<uint8_t> extract_x25519_pub(EVP_PKEY* pkey) {
    std::vector<uint8_t> pub(32);
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len);
    return pub;
}

static std::vector<uint8_t> compute_mac(const uint8_t* data, size_t data_len, const uint8_t* key, size_t key_len) {
    std::vector<uint8_t> mac(32);
    unsigned int len = 32;
    HMAC(EVP_sha256(), key, key_len, data, data_len, mac.data(), &len); // Fallback to HMAC-SHA256
    mac.resize(16); // truncate to 16 bytes
    return mac;
}

static std::vector<uint8_t> ecdh_derive(EVP_PKEY* priv, EVP_PKEY* pub) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, pub);
    size_t secret_len;
    EVP_PKEY_derive(ctx, NULL, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);
    EVP_PKEY_CTX_free(ctx);
    return secret;
}

static void hkdf_sha256(const std::vector<uint8_t>& secret, const uint8_t* salt, size_t salt_len, const char* info, uint8_t* out, size_t out_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len);
    EVP_PKEY_CTX_set1_hkdf_key(ctx, secret.data(), secret.size());
    EVP_PKEY_CTX_add1_hkdf_info(ctx, reinterpret_cast<const unsigned char*>(info), strlen(info));
    size_t olen = out_len;
    EVP_PKEY_derive(ctx, out, &olen);
    EVP_PKEY_CTX_free(ctx);
}

// Client

HandshakeClient::HandshakeClient(const uint8_t key_id[8], const uint8_t server_pubkey[32]) {
    memcpy(m_key_id, key_id, 8);
    memcpy(m_server_pubkey, server_pubkey, 32);
    m_ephemeral_pkey = generate_x25519();
}

HandshakeClient::~HandshakeClient() {
    if (m_ephemeral_pkey) EVP_PKEY_free(m_ephemeral_pkey);
}

std::vector<uint8_t> HandshakeClient::build_init() {
    std::vector<uint8_t> packet(72, 0);
    packet[0] = 0x01; // type
    memcpy(&packet[8], m_key_id, 8);

    auto pub = extract_x25519_pub(m_ephemeral_pkey);
    memcpy(&packet[16], pub.data(), 32);

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t ts_be = htobe64_compat(now);
    memcpy(&packet[48], &ts_be, 8);

    auto mac = compute_mac(packet.data(), 56, m_server_pubkey, 32);
    memcpy(&packet[56], mac.data(), 16);

    return packet;
}

bool HandshakeClient::process_resp(const uint8_t* resp, size_t len, SessionKeys& out) {
    if (len < 64 || resp[0] != 0x02) return false;

    memcpy(&out.session_id, &resp[8], 8);

    EVP_PKEY* server_ephemeral = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, &resp[16], 32);
    if (!server_ephemeral) return false;

    auto shared_secret = ecdh_derive(m_ephemeral_pkey, server_ephemeral);
    EVP_PKEY_free(server_ephemeral);

    hkdf_sha256(shared_secret, m_key_id, 8, "aegs-c2s", out.send_key, 32);
    hkdf_sha256(shared_secret, m_key_id, 8, "aegs-s2c", out.recv_key, 32);

    // Decrypt config
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t nonce[12] = {0};
    int outlen;
    uint8_t dec[16];
    
    EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, out.recv_key, nonce);
    EVP_DecryptUpdate(ctx, dec, &outlen, &resp[48], 16);
    
    out.assigned_ip = dec[0] | (dec[1] << 8) | (dec[2] << 16) | (dec[3] << 24);
    out.mtu = dec[4] | (dec[5] << 8);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Server

HandshakeServer::HandshakeServer(const std::unordered_map<uint64_t, std::string>& user_map)
    : m_user_map(user_map), m_static_pkey(nullptr), m_last_prune_time(0) {
    load_or_generate_key();
}

HandshakeServer::~HandshakeServer() {
    if (m_static_pkey) EVP_PKEY_free(m_static_pkey);
    for (auto& kv : m_pending_clients) {
        EVP_PKEY_free(kv.second.client_ephemeral_pkey);
    }
}

void HandshakeServer::load_or_generate_key() {
    std::string path = "server_key.bin";
    std::ifstream is(path, std::ios::binary);
    if (is) {
        uint8_t priv[32];
        is.read((char*)priv, 32);
        m_static_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv, 32);
    } else {
        m_static_pkey = generate_x25519();
        size_t len = 32;
        uint8_t priv[32];
        EVP_PKEY_get_raw_private_key(m_static_pkey, priv, &len);
        std::ofstream os(path, std::ios::binary);
        os.write((char*)priv, 32);
    }
}

std::vector<uint8_t> HandshakeServer::get_pubkey() const {
    return extract_x25519_pub(m_static_pkey);
}

void HandshakeServer::prune_timestamps() {
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (now - m_last_prune_time > 60000) {
        m_seen_timestamps.clear();
        m_last_prune_time = now;
    }
}

bool HandshakeServer::process_init(const uint8_t* init, size_t len, uint64_t& key_id_out) {
    if (len < 72 || init[0] != 0x01) return false;

    memcpy(&key_id_out, &init[8], 8);

    auto pub = get_pubkey();
    auto mac = compute_mac(init, 56, pub.data(), 32);
    if (memcmp(mac.data(), &init[56], 16) != 0) return false;

    uint64_t ts;
    memcpy(&ts, &init[48], 8);
    ts = be64toh_compat(ts);

    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    if (now < ts || now - ts > 30000) return false; // 30 seconds

    std::lock_guard<std::mutex> lock(m_mutex);
    prune_timestamps();
    if (m_seen_timestamps.count(ts)) return false;
    m_seen_timestamps.insert(ts);

    EVP_PKEY* client_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, &init[16], 32);
    m_pending_clients[key_id_out] = {client_pub, now};

    return true;
}

std::vector<uint8_t> HandshakeServer::build_resp(uint64_t key_id, uint32_t assigned_ip, uint16_t mtu, SessionKeys& out) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_pending_clients.find(key_id) == m_pending_clients.end()) return {};
    
    ClientState state = m_pending_clients[key_id];
    m_pending_clients.erase(key_id);

    EVP_PKEY* server_ephemeral = generate_x25519();
    auto shared_secret = ecdh_derive(server_ephemeral, state.client_ephemeral_pkey);
    EVP_PKEY_free(state.client_ephemeral_pkey);

    uint8_t key_id_bytes[8];
    memcpy(key_id_bytes, &key_id, 8);

    hkdf_sha256(shared_secret, key_id_bytes, 8, "aegs-c2s", out.recv_key, 32);
    hkdf_sha256(shared_secret, key_id_bytes, 8, "aegs-s2c", out.send_key, 32);

    RAND_bytes((uint8_t*)&out.session_id, 8);
    out.assigned_ip = assigned_ip;
    out.mtu = mtu;

    std::vector<uint8_t> resp(64, 0);
    resp[0] = 0x02;
    memcpy(&resp[8], &out.session_id, 8);
    
    auto pub = extract_x25519_pub(server_ephemeral);
    memcpy(&resp[16], pub.data(), 32);
    EVP_PKEY_free(server_ephemeral);

    // Encrypt config
    uint8_t plain_config[16] = {0};
    plain_config[0] = assigned_ip & 0xFF;
    plain_config[1] = (assigned_ip >> 8) & 0xFF;
    plain_config[2] = (assigned_ip >> 16) & 0xFF;
    plain_config[3] = (assigned_ip >> 24) & 0xFF;
    plain_config[4] = mtu & 0xFF;
    plain_config[5] = (mtu >> 8) & 0xFF;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t nonce[12] = {0};
    int outlen;
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, out.send_key, nonce);
    EVP_EncryptUpdate(ctx, &resp[48], &outlen, plain_config, 16);
    EVP_CIPHER_CTX_free(ctx);

    return resp;
}
