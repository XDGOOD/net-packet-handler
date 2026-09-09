#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Cryptographic Blackhole Responder (Anti Active Probing)
// ==============================================================================
// When the server receives an invalid/probe packet that fails authentication,
// instead of silently dropping or sending a generic error, it responds with
// a realistic QUIC-looking packet derived from the probe's own entropy.
//
// Effect: Active scanners (censorship probers) conclude this is an ordinary
// QUIC server that doesn't support their requested version, and mark the IP
// as benign.  Three response strategies are rotated pseudo-randomly:
//
//   1. QUIC Version Negotiation  (60%)  -- "I only support version X"
//   2. QUIC Retry                (20%)  -- "Please retry with this token"
//   3. QUIC Connection Close     (20%)  -- "Protocol violation, go away"
//
// All responses are rate-limited per source IP to prevent amplification.
// ==============================================================================

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

class BlackholeResponder {
public:
    BlackholeResponder() = default;

    // Generate a QUIC-looking response derived from probe entropy.
    // probe_data / probe_len: the raw invalid packet received.
    // Returns empty vector if packet is too short to derive entropy.
    std::vector<uint8_t> generate_response(const uint8_t* probe_data,
                                           size_t         probe_len);

    // Per-IP rate limiter: returns true if we should respond.
    // max_rate: minimum seconds between responses to the same IP.
    bool should_respond(const std::string& ip, double now,
                        double max_rate = 0.20);

private:
    // --- Response generators ---
    std::vector<uint8_t> quic_version_negotiation(const uint8_t* probe_data,
                                                  size_t         probe_len);
    std::vector<uint8_t> quic_retry(const uint8_t* probe_data,
                                    size_t         probe_len);
    std::vector<uint8_t> quic_connection_close(const uint8_t* probe_data,
                                               size_t         probe_len);

    // Per-IP last-response timestamp for rate limiting
    std::unordered_map<std::string, double> last_response_;
};
