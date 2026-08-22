#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <string>

struct SessionKeys {
    uint8_t send_key[32];
    uint8_t recv_key[32];
    uint64_t session_id;
    uint32_t assigned_ip;
    uint16_t mtu;
};

// Forward declaration for OpenSSL EVP_PKEY
struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;

class HandshakeClient {
public:
    HandshakeClient(const uint8_t key_id[8], const uint8_t server_pubkey[32]);
    ~HandshakeClient();

    std::vector<uint8_t> build_init();
    bool process_resp(const uint8_t* resp, size_t len, SessionKeys& out);

private:
    uint8_t m_key_id[8];
    uint8_t m_server_pubkey[32];
    EVP_PKEY* m_ephemeral_pkey;
};

class HandshakeServer {
public:
    HandshakeServer(const std::unordered_map<uint64_t, std::string>& user_map);
    ~HandshakeServer();

    bool process_init(const uint8_t* init, size_t len, uint64_t& key_id_out);
    std::vector<uint8_t> build_resp(uint64_t key_id, uint32_t assigned_ip, uint16_t mtu, SessionKeys& out);
    std::vector<uint8_t> get_pubkey() const;

private:
    std::unordered_map<uint64_t, std::string> m_user_map;
    EVP_PKEY* m_static_pkey;

    std::mutex m_mutex;
    std::unordered_set<uint64_t> m_seen_timestamps;
    uint64_t m_last_prune_time;

    struct ClientState {
        EVP_PKEY* client_ephemeral_pkey;
        uint64_t timestamp;
    };
    std::unordered_map<uint64_t, ClientState> m_pending_clients;

    void load_or_generate_key();
    void prune_timestamps();
};
