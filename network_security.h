#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Network Security & Reliability Suite
// - Component 1: KillSwitch (Hardware/Firewall-level Traffic Leak Prevention)
// - Component 2: DnsLeakProtector (Port 53 Lockdown & Resolver Shield)
// - Component 3: TransportFailureDetector (Loss monitoring for TCP fallback)
// ==============================================================================

#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include <chrono>

class KillSwitch {
public:
    KillSwitch() noexcept;
    ~KillSwitch();

    KillSwitch(const KillSwitch&) = delete;
    KillSwitch& operator=(const KillSwitch&) = delete;

    // Activates firewall rules:
    // 1. Allow traffic to server_ip on [base_port .. base_port + port_count - 1]
    // 2. Allow all traffic on tun_iface (e.g. "aegs0")
    // 3. Allow loopback traffic ("lo" / 127.0.0.1)
    // 4. Allow DHCP client traffic (UDP 67/68) to preserve local leases
    // 5. DROP all other outbound traffic on physical interfaces
    bool enable(const std::string& server_ip,
                uint16_t           base_port,
                int                port_count  = 1,
                const std::string& tun_iface   = "aegs0") noexcept;

    // Reverts all firewall rules cleanly
    bool disable() noexcept;

    bool is_active() const noexcept { return active_; }

    // Generates the exact shell commands needed for audit/dry-run
    std::vector<std::string> generate_rules(const std::string& server_ip,
                                           uint16_t           base_port,
                                           int                port_count,
                                           const std::string& tun_iface) const;

private:
    bool active_;
    std::string server_ip_;
    uint16_t base_port_;
    int port_count_;
    std::string tun_iface_;
    std::vector<std::string> applied_cleanup_commands_;

    int execute_command(const std::string& cmd) const noexcept;
};

class DnsLeakProtector {
public:
    DnsLeakProtector() noexcept;
    ~DnsLeakProtector();

    DnsLeakProtector(const DnsLeakProtector&) = delete;
    DnsLeakProtector& operator=(const DnsLeakProtector&) = delete;

    // Activates DNS leak shield:
    // 1. Blocks outbound UDP/TCP 53 on all non-TUN interfaces
    // 2. Overrides /etc/resolv.conf with secure nameserver (e.g. 10.8.0.1)
    // 3. Backs up previous resolv.conf for atomic restoration on exit
    bool enable(const std::string& tun_iface   = "aegs0",
                const std::string& secure_dns  = "10.8.0.1") noexcept;

    bool disable() noexcept;

    bool is_active() const noexcept { return active_; }

    std::vector<std::string> generate_rules(const std::string& tun_iface) const;

private:
    bool active_;
    std::string tun_iface_;
    std::string secure_dns_;
    std::string original_resolv_conf_;
    bool resolv_conf_backed_up_;

    int execute_command(const std::string& cmd) const noexcept;
};

class TransportFailureDetector {
public:
    explicit TransportFailureDetector(int max_consecutive_timeouts = 5,
                                      double max_blackout_sec = 15.0) noexcept;

    void record_success() noexcept;
    void record_timeout() noexcept;
    void record_packet_loss(size_t sent, size_t lost) noexcept;

    // Returns true if UDP is deemed completely blocked and fallback to TCP is required
    bool should_fallback_to_tcp() const noexcept;

    int consecutive_timeouts() const noexcept { return consecutive_timeouts_; }
    double loss_rate() const noexcept;

    void reset() noexcept;

private:
    int max_consecutive_timeouts_;
    double max_blackout_sec_;
    int consecutive_timeouts_;
    size_t total_sent_;
    size_t total_lost_;
    std::chrono::steady_clock::time_point last_success_time_;
};
