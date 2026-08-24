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
#include <openssl/kdf.h>
#include <chrono>
#include <thread>
#include <mutex>

#include "tun_interface.h"
#include "ip_router.h"
#include "handshake.h"
#include "ip_pool.h"
#include "nat_manager.h"

// --- AEGS Protocol v2 Constants ---
// AWG v1/v2/v3 Obfuscation & Noise Architecture + VLESS-REALITY Mimicry
const std::string VER_MAGIC = "AG2\x01"; // 4-byte internal magic post unmasking
const std::string WG_HOST = "wg-core";
const int WG_PORT = 51820;
const std::string DB_PATH = "/app/data/aegis.db";
const int MAX_EVENTS = 1024;

const size_t BUFFER_SIZE = 64000;
const size_t PAD_MIN = 32;
const size_t PAD_MAX = 256;
const size_t FRAME_HDR = 2;
const size_t TAG_LEN = 16;
const size_t INTERNAL_BUF_SIZE = 65535;

const int PBKDF2_ITERATIONS = 200000;

// --- Key & Header Mask Derivation (HKDF-SHA256) ---
bool derive_master_key(const std::string& token, const std::string& salt, uint8_t* master_key_out) {
    return PKCS5_PBKDF2_HMAC(token.c_str(), (int)token.length(),
                              reinterpret_cast<const unsigned char*>(salt.c_str()), (int)salt.length(),
                              PBKDF2_ITERATIONS, EVP_sha256(), 32, master_key_out) == 1;
}

bool hkdf_expand(const uint8_t* master_key, size_t master_key_len, const std::string& info, uint8_t* out, size_t out_len) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!pctx) return false;
    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const unsigned char*)"aegis-v2-salt", 13) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, master_key, (int)master_key_len) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char*)info.data(), (int)info.size()) <= 0 ||
        EVP_PKEY_derive(pctx, out, &out_len) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);
    return true;
}

// AWG v3 Dynamic Header Masking (ChaCha20 Stream Cipher)
bool mask_unmask_header(const uint8_t* in, size_t len, const uint8_t* mask_key, const uint8_t* hdr_iv, uint8_t* out) {
    uint8_t full_iv[16] = {0};
    std::memcpy(full_iv + 4, hdr_iv, 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int outlen = 0;
    if (EVP_CipherInit_ex(ctx, EVP_chacha20(), NULL, mask_key, full_iv, 1) != 1 ||
        EVP_CipherUpdate(ctx, out, &outlen, in, (int)len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int final_len = 0;
    EVP_CipherFinal_ex(ctx, out + outlen, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
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
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    if (EVP_DecryptFinal_ex(ctx, pt + len, &len) <= 0) { EVP_CIPHER_CTX_free(ctx); return false; }
    total_len += len;
    pt_len = total_len;
    EVP_CIPHER_CTX_free(ctx); return true;
}

// RFC 6479 / Linux WireGuard 64-bit Sliding Window Anti-Replay Filter
class AntiReplayFilter {
    uint64_t last_seq = 0;
    uint64_t bitmap = 0;
public:
    bool check_and_update(uint64_t seq) {
        if (seq == 0) return true; // Replay/Invalid
        if (seq > last_seq) {
            uint64_t diff = seq - last_seq;
            if (diff < 64) {
                bitmap = (bitmap << diff) | 1ULL;
            } else {
                bitmap = 1ULL;
            }
            last_seq = seq;
            return false; // Valid and updated
        }
        uint64_t diff = last_seq - seq;
        if (diff >= 64) return true; // Out of sliding window (too old) -> reject
        if (bitmap & (1ULL << diff)) return true; // Already seen -> replay detected
        bitmap |= (1ULL << diff);
        return false; // Valid out-of-order packet accepted
    }
};

struct Session {
    std::string key_id_hex;
    uint8_t master_key[32];
    uint8_t mask_key[32];
    uint8_t payload_key[32];
    struct sockaddr_in client_addr {};
    bool has_client = false;
    double last_activity = 0;
    uint64_t tx_seq = 0;
    AntiReplayFilter replay_filter;
    uint64_t session_id = 0;     // NEW: AEGS v3 session ID from handshake
    uint32_t assigned_ip = 0;    // NEW: assigned TUN IP (host byte order)
    SessionKeys session_keys;    // NEW: ECDH-derived per-session keys
    bool v3_handshake_done = false; // NEW: true after ECDH handshake complete

    bool check_replay(const uint8_t* n_bytes) {
        uint64_t seq = 0;
        std::memcpy(&seq, n_bytes, sizeof(uint64_t));
        return replay_filter.check_and_update(seq);
    }
};

std::unordered_map<std::string, Session*> sessions;
std::unordered_map<uint32_t, Session*> ip_to_session;
std::mutex sessions_mu;

struct FailRecord { 
    double weight = 0; 
    double last_seen = 0; 
    int level = 0; 
    double last_fallback_dns = 0; // Token bucket rate limiter for DNS mimicry
};
std::unordered_map<std::string, FailRecord> failed_attempts;
std::unordered_map<std::string, double> banned_ips;
const int ban_levels[] = {0, 30, 300, 3600};

double last_cleanup = 0;
const double CLEANUP_INTERVAL = 30.0;
const double FAIL_IDLE_TTL = 300.0;
const double SESSION_IDLE_TIMEOUT = 180.0; // 3 minutes idle -> close inactive session

void cleanup_maps(double now, int epoll_fd) {
    if (now - last_cleanup < CLEANUP_INTERVAL) return;
    last_cleanup = now;

    for (auto it = banned_ips.begin(); it != banned_ips.end(); ) {
        if (now > it->second) it = banned_ips.erase(it); else ++it;
    }
    for (auto it = failed_attempts.begin(); it != failed_attempts.end(); ) {
        if (now - it->second.last_seen > FAIL_IDLE_TTL) it = failed_attempts.erase(it); else ++it;
    }
    for (auto it = sessions.begin(); it != sessions.end(); ) {
        Session* s = it->second;
        if (s->has_client && (now - s->last_activity > SESSION_IDLE_TIMEOUT)) {
            std::cerr << "[GC] Session " << s->key_id_hex << " idle timeout\n";
            if (s->assigned_ip) ip_to_session.erase(s->assigned_ip);
            s->has_client = false;
            s->v3_handshake_done = false;
            s->assigned_ip = 0;
        }
        ++it;
    }
}

bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

// Rate-limited VLESS-REALITY Probing Fallback Response (DNS FORMERR)
void send_probing_fallback(int fd, const struct sockaddr_in& caddr, FailRecord& rec, double now) {
    // Rate limit: max 5 responses/sec per scanning IP to prevent amplification/CPU starvation
    if (now - rec.last_fallback_dns < 0.20) return;
    rec.last_fallback_dns = now;

    static const uint8_t fake_dns_formerr[12] = {
        0x00, 0x00, // Query ID
        0x81, 0x81, // Flags: Response, Opcode 0, FormErr (RCODE 1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    sendto(fd, fake_dns_formerr, sizeof(fake_dns_formerr), 0, (struct sockaddr*)&caddr, sizeof(caddr));
}

void record_fail(int fd, const struct sockaddr_in& caddr, const std::string& ip, double now, double weight) {
    auto& rec = failed_attempts[ip];
    if (rec.level == 0) rec.level = 1;
    if (now - rec.last_seen > 120.0) { rec.weight = 0; }
    rec.last_seen = now;
    rec.weight += weight;
    
    send_probing_fallback(fd, caddr, rec, now);

    if (rec.weight >= 10.0) {
        int lvl = std::min(rec.level, 3);
        banned_ips[ip] = now + ban_levels[lvl];
        rec.weight = 0; rec.level = lvl + 1;
    }
}

size_t secure_pad_len() {
    uint8_t b;
    RAND_bytes(&b, 1);
    return PAD_MIN + (b % (PAD_MAX - PAD_MIN + 1));
}

uint16_t generate_junk_len() {
    uint8_t b; RAND_bytes(&b, 1);
    if (b < 50) {
        return 16 + (b % 49);
    }
    return 0;
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
                if (!derive_master_key(token, s->key_id_hex, s->master_key) ||
                    !hkdf_expand(s->master_key, 32, "aegis-v2-header-mask", s->mask_key, 32) ||
                    !hkdf_expand(s->master_key, 32, "aegis-v2-payload-key", s->payload_key, 32)) {
                    std::cerr << "key derivation / HKDF failed for " << s->key_id_hex << "\n";
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
    
    std::unordered_map<uint64_t, std::string> user_map;
    // FIX CRIT-1: Build master_key_map so HandshakeServer can verify MAC
    // using user's MasterKey (secret), not the server's public key.
    std::unordered_map<uint64_t, std::vector<uint8_t>> master_key_map;
    for (auto& kv : sessions) {
        uint64_t kid = 0;
        for (int i = 0; i < 8; i++) {
            unsigned int b;
            sscanf(kv.second->key_id_hex.c_str() + i*2, "%02x", &b);
            ((uint8_t*)&kid)[i] = (uint8_t)b;
        }
        user_map[kid] = kv.first; 
        master_key_map[kid] = std::vector<uint8_t>(
            kv.second->master_key, kv.second->master_key + 32);
    }
    
    TunInterface tun("aegs0", "10.8.0.1/24", 1400);
    if (!tun.open()) {
        std::cerr << "[AEGS v3] Failed to create TUN interface aegs0\n";
        return 1;
    }
    std::cout << "[AEGS v3] TUN interface aegs0 (10.8.0.1/24) ready\n";

    std::string out_iface = NatManager::detect_outbound_iface();
    NatManager nat("aegs0", out_iface, "10.8.0.0/24");
    if (!nat.setup()) {
        std::cerr << "[AEGS v3] Warning: NAT setup failed (may need root)\n";
    } else {
        std::cout << "[AEGS v3] NAT/MASQUERADE active on " << out_iface << "\n";
    }

    IpPool ip_pool("10.8.0.0/24");
    HandshakeServer hs_server(user_map, master_key_map);
    auto server_pubkey = hs_server.get_pubkey();

    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }
    if (!set_nonblocking(server_fd)) { perror("fcntl"); return 1; }

    int sock_buf_size = 4 * 1024 * 1024; // 4MB socket buffer for high throughput
    setsockopt(server_fd, SOL_SOCKET, SO_RCVBUF, &sock_buf_size, sizeof(sock_buf_size));
    setsockopt(server_fd, SOL_SOCKET, SO_SNDBUF, &sock_buf_size, sizeof(sock_buf_size));
    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in saddr {};
    saddr.sin_family = AF_INET; saddr.sin_addr.s_addr = INADDR_ANY; saddr.sin_port = htons(50001);
    if (bind(server_fd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0) { perror("bind"); return 1; }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) { perror("epoll_create1"); return 1; }
    struct epoll_event ev {}, events[MAX_EVENTS];
    ev.events = EPOLLIN; ev.data.fd = server_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);
    
    int tun_fd = tun.fd();
    ev.events = EPOLLIN; ev.data.fd = tun_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd, &ev);

    std::vector<uint8_t> buffer(BUFFER_SIZE);
    std::vector<uint8_t> dec_buf(INTERNAL_BUF_SIZE);
    std::vector<uint8_t> enc_buf(INTERNAL_BUF_SIZE);

    std::cout << "[AEGS v2/v3 Server] Epoll obfuscated listener active on 0.0.0.0:50001\n";

    while (true) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        double now = std::chrono::duration<double>(std::chrono::system_clock::now().time_since_epoch()).count();
        cleanup_maps(now, epoll_fd);

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;

            if (fd == server_fd) {
                struct sockaddr_in caddr; socklen_t clen = sizeof(caddr);
                ssize_t len = recvfrom(fd, buffer.data(), buffer.size(), 0, (struct sockaddr*)&caddr, &clen);
                if (len < 0) continue;

                std::string ip = inet_ntoa(caddr.sin_addr);
                auto ban_it = banned_ips.find(ip);
                if (ban_it != banned_ips.end() && now < ban_it->second) continue;

                if (buffer[0] == 0x01 && (size_t)len >= 72) {
                    uint64_t key_id_out = 0;
                    if (hs_server.process_init(buffer.data(), len, key_id_out)) {
                        char kid_hex[17];
                        for (int j = 0; j < 8; j++) sprintf(&kid_hex[j*2], "%02x", ((uint8_t*)&key_id_out)[j]);
                        kid_hex[16] = 0;
                        auto sit = sessions.find(kid_hex);
                        if (sit != sessions.end()) {
                            Session* s = sit->second;
                            auto maybe_ip = ip_pool.allocate();
                            if (!maybe_ip) { std::cerr << "IP pool exhausted\n"; continue; }
                            if (s->assigned_ip) { ip_pool.release(s->assigned_ip); ip_to_session.erase(s->assigned_ip); }
                            s->assigned_ip = *maybe_ip;
                            ip_to_session[s->assigned_ip] = s;
                            
                            SessionKeys sk;
                            auto resp = hs_server.build_resp(key_id_out, s->assigned_ip, 1400, sk);
                            s->session_keys = sk;
                            s->session_id = sk.session_id;
                            s->client_addr = caddr;
                            s->has_client = true;
                            s->v3_handshake_done = true;
                            s->last_activity = now;
                            sendto(server_fd, resp.data(), resp.size(), 0, (struct sockaddr*)&caddr, sizeof(caddr));
                            std::cout << "[HS] Client " << ip << " assigned " << IpPool::to_string(s->assigned_ip) << "\n";
                        }
                    }
                    continue;
                }

                // AEGS v2 Min Outer Size: HDR_IV(12) + MASKED_HDR(16) + AEAD_IV(12) + TAG(16) = 56 bytes
                if (len < 56) { record_fail(server_fd, caddr, ip, now, 1.0); continue; }

                const uint8_t* hdr_iv = buffer.data();
                Session* matched_sess = nullptr;
                uint8_t unmasked_hdr[16];

                // Attempt to unmask header against registered user sessions
                for (auto& kv : sessions) {
                    Session* s = kv.second;
                    if (mask_unmask_header(buffer.data() + 12, 16, s->mask_key, hdr_iv, unmasked_hdr)) {
                        char kid[17];
                        for (int j = 0; j < 8; ++j) sprintf(&kid[j * 2], "%02x", unmasked_hdr[j]);
                        kid[16] = '\0';
                        if (s->key_id_hex == kid && std::memcmp(unmasked_hdr + 12, VER_MAGIC.data(), 4) == 0) {
                            matched_sess = s;
                            break;
                        }
                    }
                }

                if (!matched_sess) { record_fail(server_fd, caddr, ip, now, 1.0); continue; }

                Session* s = matched_sess;
                s->client_addr = caddr; s->has_client = true;
                s->last_activity = now;

                uint16_t junk_len = (unmasked_hdr[8] << 8) | unmasked_hdr[9];
                size_t aead_offset = 12 + 16 + junk_len;
                if ((size_t)len < aead_offset + 12 + TAG_LEN) { record_fail(server_fd, caddr, ip, now, 0.5); continue; }

                const uint8_t* aead_nonce = buffer.data() + aead_offset;
                if (s->check_replay(aead_nonce)) continue;

                const uint8_t* ct = buffer.data() + aead_offset + 12;
                size_t ct_len = len - (aead_offset + 12);

                size_t dec_len = 0;
                const uint8_t* dec_key = s->v3_handshake_done ? s->session_keys.send_key : s->payload_key;
                if (!chacha20_poly1305_decrypt(ct, ct_len, dec_key, aead_nonce, dec_buf.data(), dec_len)) {
                    record_fail(server_fd, caddr, ip, now, 0.5); continue;
                }

                failed_attempts.erase(ip);

                if (dec_len < 2) continue;
                uint16_t plen = (dec_buf[0] << 8) | dec_buf[1];
                if (plen > 0 && plen <= dec_len - 2) {
                    tun.write_packet(dec_buf.data() + 2, plen);  
                }

            } else if (fd == tun_fd) {
                ssize_t n = tun.read_packet(buffer.data(), buffer.size());
                if (n < 20) continue; 

                uint32_t dst_ip = (uint32_t(buffer[16]) << 24) | (uint32_t(buffer[17]) << 16)
                                | (uint32_t(buffer[18]) << 8)  |  uint32_t(buffer[19]);

                auto ip_it = ip_to_session.find(dst_ip);
                if (ip_it == ip_to_session.end()) continue;  
                Session* s = ip_it->second;
                if (!s->has_client) continue;
                s->last_activity = now;

                const uint8_t* enc_key = s->v3_handshake_done ? s->session_keys.recv_key : s->payload_key;

                size_t pad_len = secure_pad_len();
                size_t frame_len = FRAME_HDR + (size_t)n + pad_len;
                if (frame_len + TAG_LEN > dec_buf.size()) { pad_len = 0; frame_len = FRAME_HDR + (size_t)n; }

                uint16_t plen_be = htons((uint16_t)n);
                std::memcpy(dec_buf.data(), &plen_be, 2);
                std::memcpy(dec_buf.data() + 2, buffer.data(), (size_t)n);
                if (pad_len > 0) RAND_bytes(dec_buf.data() + 2 + n, (int)pad_len);

                uint8_t aead_nonce[12] = {0};
                s->tx_seq++;
                std::memcpy(aead_nonce, &s->tx_seq, sizeof(uint64_t));
                RAND_bytes(aead_nonce + 8, 4);

                size_t enc_len = 0;
                if (chacha20_poly1305_encrypt(dec_buf.data(), frame_len, enc_key, aead_nonce, enc_buf.data(), enc_len)) {
                    uint16_t junk_len = generate_junk_len();

                    uint8_t raw_kid[8];
                    for (int k = 0; k < 8; ++k) {
                        unsigned int b; std::sscanf(s->key_id_hex.c_str() + (k * 2), "%02x", &b);
                        raw_kid[k] = (uint8_t)b;
                    }

                    uint8_t hdr_plain[16];
                    std::memcpy(hdr_plain, raw_kid, 8);
                    hdr_plain[8] = (junk_len >> 8) & 0xFF;
                    hdr_plain[9] = junk_len & 0xFF;
                    hdr_plain[10] = 0; hdr_plain[11] = 0;
                    std::memcpy(hdr_plain + 12, VER_MAGIC.data(), 4);

                    uint8_t hdr_iv[12]; RAND_bytes(hdr_iv, 12);
                    uint8_t masked_hdr[16];
                    if (mask_unmask_header(hdr_plain, 16, s->mask_key, hdr_iv, masked_hdr)) {
                        static thread_local std::vector<uint8_t> out_buf(BUFFER_SIZE);
                        size_t out_len = 0;
                        std::memcpy(out_buf.data(), hdr_iv, 12); out_len += 12;
                        std::memcpy(out_buf.data() + out_len, masked_hdr, 16); out_len += 16;
                        if (junk_len > 0) {
                            RAND_bytes(out_buf.data() + out_len, (int)junk_len);
                            out_len += junk_len;
                        }
                        std::memcpy(out_buf.data() + out_len, aead_nonce, 12); out_len += 12;
                        std::memcpy(out_buf.data() + out_len, enc_buf.data(), enc_len); out_len += enc_len;

                        sendto(server_fd, out_buf.data(), out_len, 0, (struct sockaddr*)&s->client_addr, sizeof(s->client_addr));
                    }
                }
            }
        }
    }

    nat.teardown();
    tun.close();
    return 0;
}
