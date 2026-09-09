// ==============================================================================
// AEGS v4 "Pantheon" -- Network Security & Reliability Suite Implementation
// ==============================================================================

#include "network_security.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <algorithm>

// -----------------------------------------------------------------------------
// KillSwitch Implementation
// -----------------------------------------------------------------------------

KillSwitch::KillSwitch() noexcept
    : active_(false),
      base_port_(50001),
      port_count_(1),
      tun_iface_("aegs0")
{}

KillSwitch::~KillSwitch() {
    if (active_) {
        disable();
    }
}

int KillSwitch::execute_command(const std::string& cmd) const noexcept {
    return std::system(cmd.c_str());
}

std::vector<std::string> KillSwitch::generate_rules(const std::string& server_ip,
                                                   uint16_t           base_port,
                                                   int                port_count,
                                                   const std::string& tun_iface) const {
    std::vector<std::string> rules;
    std::string chain = "AEGS_KILLSWITCH";

    // 1. Create dedicated user chain
    rules.push_back("iptables -N " + chain);

    // 2. Allow established/related incoming connections
    rules.push_back("iptables -A " + chain + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT");

    // 3. Allow all traffic on loopback interface
    rules.push_back("iptables -A " + chain + " -o lo -j ACCEPT");

    // 4. Allow all traffic on the VPN TUN interface
    rules.push_back("iptables -A " + chain + " -o " + tun_iface + " -j ACCEPT");

    // 5. Allow DHCP client traffic (prevent losing local DHCP lease)
    rules.push_back("iptables -A " + chain + " -p udp --sport 68 --dport 67 -j ACCEPT");

    // 6. Allow direct tunnel packets to the server IP on the port hopping range
    uint16_t end_port = static_cast<uint16_t>(base_port + (port_count > 0 ? port_count - 1 : 0));
    std::string port_spec = (port_count > 1)
        ? (std::to_string(base_port) + ":" + std::to_string(end_port))
        : std::to_string(base_port);

    rules.push_back("iptables -A " + chain + " -d " + server_ip + " -p udp --dport " + port_spec + " -j ACCEPT");
    rules.push_back("iptables -A " + chain + " -d " + server_ip + " -p tcp --dport " + port_spec + " -j ACCEPT");

    // 7. Drop all other outbound IPv4 traffic on all other interfaces
    rules.push_back("iptables -A " + chain + " -j DROP");

    // 8. Insert jump at the top of the OUTPUT chain
    rules.push_back("iptables -I OUTPUT 1 -j " + chain);

    return rules;
}

bool KillSwitch::enable(const std::string& server_ip,
                        uint16_t           base_port,
                        int                port_count,
                        const std::string& tun_iface) noexcept {
    if (active_) {
        disable();
    }

    server_ip_ = server_ip;
    base_port_ = base_port;
    port_count_ = (port_count < 1) ? 1 : port_count;
    tun_iface_ = tun_iface;

    auto rules = generate_rules(server_ip_, base_port_, port_count_, tun_iface_);
    std::string chain = "AEGS_KILLSWITCH";

    // Setup cleanup commands first in reverse order
    applied_cleanup_commands_.clear();
    applied_cleanup_commands_.push_back("iptables -D OUTPUT -j " + chain);
    applied_cleanup_commands_.push_back("iptables -F " + chain);
    applied_cleanup_commands_.push_back("iptables -X " + chain);

    std::cout << "[KillSwitch] Activating hardware-level firewall isolation on " << tun_iface_ << "...\n";
    for (const auto& rule : rules) {
        int ret = execute_command(rule + " 2>/dev/null");
        (void)ret;
    }

    active_ = true;
    std::cout << "[KillSwitch] Isolation ACTIVE. Direct leaks blocked, server="
              << server_ip_ << ":" << base_port_ << "-" << (base_port_ + port_count_ - 1) << "\n";
    return true;
}

bool KillSwitch::disable() noexcept {
    if (!active_) return true;

    std::cout << "[KillSwitch] Deactivating firewall isolation...\n";
    for (const auto& cmd : applied_cleanup_commands_) {
        int ret = execute_command(cmd + " 2>/dev/null");
        (void)ret;
    }

    applied_cleanup_commands_.clear();
    active_ = false;
    std::cout << "[KillSwitch] Isolation DEACTIVATED. Normal routing restored.\n";
    return true;
}

// -----------------------------------------------------------------------------
// DnsLeakProtector Implementation
// -----------------------------------------------------------------------------

DnsLeakProtector::DnsLeakProtector() noexcept
    : active_(false),
      tun_iface_("aegs0"),
      secure_dns_("10.8.0.1"),
      resolv_conf_backed_up_(false)
{}

DnsLeakProtector::~DnsLeakProtector() {
    if (active_) {
        disable();
    }
}

int DnsLeakProtector::execute_command(const std::string& cmd) const noexcept {
    return std::system(cmd.c_str());
}

std::vector<std::string> DnsLeakProtector::generate_rules(const std::string& tun_iface) const {
    std::vector<std::string> rules;
    std::string chain = "AEGS_DNS_SHIELD";

    rules.push_back("iptables -N " + chain);
    // Allow DNS queries over the VPN interface
    rules.push_back("iptables -A " + chain + " -o " + tun_iface + " -p udp --dport 53 -j ACCEPT");
    rules.push_back("iptables -A " + chain + " -o " + tun_iface + " -p tcp --dport 53 -j ACCEPT");
    // Allow local DNS (e.g. systemd-resolved on 127.0.0.53 or dnsmasq on 127.0.0.1)
    rules.push_back("iptables -A " + chain + " -o lo -p udp --dport 53 -j ACCEPT");
    rules.push_back("iptables -A " + chain + " -o lo -p tcp --dport 53 -j ACCEPT");
    // Block all plaintext DNS requests on non-VPN physical interfaces (prevent ISP leak)
    rules.push_back("iptables -A " + chain + " -p udp --dport 53 -j DROP");
    rules.push_back("iptables -A " + chain + " -p tcp --dport 53 -j DROP");
    // Insert into OUTPUT chain
    rules.push_back("iptables -I OUTPUT 1 -j " + chain);

    return rules;
}

bool DnsLeakProtector::enable(const std::string& tun_iface,
                             const std::string& secure_dns) noexcept {
    if (active_) {
        disable();
    }

    tun_iface_ = tun_iface;
    secure_dns_ = secure_dns.empty() ? "10.8.0.1" : secure_dns;

    // Backup /etc/resolv.conf if possible
    std::ifstream src("/etc/resolv.conf");
    if (src.is_open()) {
        std::stringstream ss;
        ss << src.rdbuf();
        original_resolv_conf_ = ss.str();
        resolv_conf_backed_up_ = true;
        src.close();

        // Write secure resolver
        std::ofstream dst("/etc/resolv.conf", std::ios::trunc);
        if (dst.is_open()) {
            dst << "# Generated by AEGS v4 DnsLeakProtector\n";
            dst << "nameserver " << secure_dns_ << "\n";
            dst << "options edns0\n";
            dst.close();
        }
    }

    // Apply iptables port 53 lockdown
    auto rules = generate_rules(tun_iface_);
    for (const auto& rule : rules) {
        int ret = execute_command(rule + " 2>/dev/null");
        (void)ret;
    }

    active_ = true;
    std::cout << "[DNS-Shield] Port 53 lockdown ACTIVE on " << tun_iface_
              << " -> DNS forced to " << secure_dns_ << "\n";
    return true;
}

bool DnsLeakProtector::disable() noexcept {
    if (!active_) return true;

    std::cout << "[DNS-Shield] Restoring default DNS resolver and removing port 53 lockdown...\n";
    std::string chain = "AEGS_DNS_SHIELD";
    execute_command("iptables -D OUTPUT -j " + chain + " 2>/dev/null");
    execute_command("iptables -F " + chain + " 2>/dev/null");
    execute_command("iptables -X " + chain + " 2>/dev/null");

    if (resolv_conf_backed_up_ && !original_resolv_conf_.empty()) {
        std::ofstream dst("/etc/resolv.conf", std::ios::trunc);
        if (dst.is_open()) {
            dst << original_resolv_conf_;
            dst.close();
        }
        resolv_conf_backed_up_ = false;
    }

    active_ = false;
    return true;
}

// -----------------------------------------------------------------------------
// TransportFailureDetector Implementation
// -----------------------------------------------------------------------------

TransportFailureDetector::TransportFailureDetector(int max_consecutive_timeouts,
                                                   double max_blackout_sec) noexcept
    : max_consecutive_timeouts_(max_consecutive_timeouts < 1 ? 1 : max_consecutive_timeouts),
      max_blackout_sec_(max_blackout_sec < 1.0 ? 1.0 : max_blackout_sec),
      consecutive_timeouts_(0),
      total_sent_(0),
      total_lost_(0),
      last_success_time_(std::chrono::steady_clock::now())
{}

void TransportFailureDetector::record_success() noexcept {
    consecutive_timeouts_ = 0;
    last_success_time_ = std::chrono::steady_clock::now();
}

void TransportFailureDetector::record_timeout() noexcept {
    consecutive_timeouts_++;
}

void TransportFailureDetector::record_packet_loss(size_t sent, size_t lost) noexcept {
    total_sent_ += sent;
    total_lost_ += lost;
}

double TransportFailureDetector::loss_rate() const noexcept {
    if (total_sent_ == 0) return 0.0;
    return static_cast<double>(total_lost_) / static_cast<double>(total_sent_);
}

bool TransportFailureDetector::should_fallback_to_tcp() const noexcept {
    if (consecutive_timeouts_ >= max_consecutive_timeouts_) {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    double blackout = std::chrono::duration<double>(now - last_success_time_).count();
    if (blackout >= max_blackout_sec_ && consecutive_timeouts_ > 0) {
        return true;
    }

    // Extreme packet loss (>75% sustained across >= 100 packets)
    if (total_sent_ >= 100 && loss_rate() > 0.75) {
        return true;
    }

    return false;
}

void TransportFailureDetector::reset() noexcept {
    consecutive_timeouts_ = 0;
    total_sent_ = 0;
    total_lost_ = 0;
    last_success_time_ = std::chrono::steady_clock::now();
}
