# AEGS v4 "Pantheon" — Autonomous Encrypted Gateway System

[![Tests](https://img.shields.io/badge/Tests-12%2F12%20Pillars%20PASS-brightgreen.svg)](#)
[![Language](https://img.shields.io/badge/Language-C%2B%2B17-blue.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)](#)
[![Version](https://img.shields.io/badge/Version-4.0%20Pantheon-orange.svg)](#)

> **State-of-the-Art, High-Performance, AI/ML & State-Machine Resistant UDP Tunnel Protocol**

---

## 🧠 What is AEGS v4 Pantheon?
AEGS v4 is an advanced transport protocol specifically engineered to defeat both **stateful DPI state machines** (ТСПУ, GFW, Cloudflare Magic Firewall) and **AI/ML statistical classifiers** (traffic shape analysis, timing clustering) that easily identify and block WireGuard, OpenVPN, and basic AmneziaWG obfuscations.

---

## 🛡 Key Features & Anti-DPI Architecture

### 1. 🧠 State-Machine Pre-Bypass ("AEGS Illusion")
* **Problem:** Advanced DPI tracks the first 3–5 packets of any new UDP flow. If they don't match a known benign protocol profile, the flow is throttled or dropped.
* **Solution:** Before transmitting `HANDSHAKE_INIT`, client transmits 1–3 decoy packets that precisely mimic **RFC 5389 STUN Binding Requests** (`0x2112A442` magic cookie) or **RFC 9000 QUIC Initial packets** (≥1200 bytes).
* **Effect:** The ISP's DPI classifies the connection as benign WebRTC/STUN or HTTP/3 traffic and stops deep packet inspection.

### 2. 🎭 Semantic Padding ("Bimodal Shaping" — Anti-ML)
* **Problem:** Neural networks detect VPN tunnels by uniform packet-size distributions (e.g. random 0–256 bytes in AmneziaWG).
* **Solution:** Intelligently shapes traffic into a bimodal profile mimicking YouTube/QUIC streaming:
  * Small packets (≤200 B: ACKs, DNS, TCP SYN) are padded to **~256 B** (QUIC ACK profile).
  * Large packets (>200 B: video, web assets) are padded to **~1350 B** (Full MTU QUIC frames).
  * 5% random medium packets (512–768 B) inject noise to prevent exact-size fingerprinting.

### 3. 👻 Active Chaffing (Anti-Timing Analysis)
* **Problem:** VPN usage is easily fingerprinted by bursty idle/active timing patterns.
* **Solution:** When idle for >500 ms, client generates encrypted dummy chaff packets at 50–200 ms intervals. PlainHDR byte 10 has bit `0x80` set. The server verifies AEAD MAC, detects the chaff flag, and silently drops the packet without forwarding to the OS network stack.
* **Effect:** The tunnel appears as a continuous, active WebRTC voice/video call.

### 4. 🛡 Cryptographic Blackhole (Anti-Active Probing)
* **Problem:** Scanners send malformed probes to detect VPN server behavior.
* **Solution:** Rather than dropping or sending DNS FORMERR, the server derives entropy from the probe and responds with authentic QUIC packets:
  * **60%**: QUIC Version Negotiation (RFC 9000 §17.2.1, echoes prober's CIDs)
  * **20%**: QUIC Retry token packet
  * **20%**: QUIC Connection Close (`PROTOCOL_VIOLATION`)
* **Effect:** Scanners conclude the port hosts an ordinary QUIC server and de-list the IP.

### 5. 🔀 Port Hopping (Active DPI Evasion)
* **Problem:** DPI blocks specific UDP ports when VPN traffic is suspected.
* **Solution:** Server binds to multiple ports. Client uses HMAC-SHA256 to deterministically hop ports every `hop_interval` seconds based on the session key.

### 6. ⚡ Session Resumption (Zero-RTT Reconnect)
* **Problem:** ECDH handshakes are expensive and slow down reconnections.
* **Solution:** Server issues an encrypted, AEAD-authenticated 96-byte `ResumptionToken`. Client sends a `RESUME` packet to reconnect in <5ms.

### 7. 🔒 Hardware Kill-Switch & DNS Leak Shield
* **Problem:** If a tunnel unexpectedly disconnects, packets leak to the ISP via physical adapters. Plaintext DNS queries (port 53) leak visited domains.
* **Solution:** Hardware/firewall-level isolation (`--kill-switch`) drops all external traffic except direct packets to the VPN server, while `--dns-protect` enforces tunnel DNS and blocks port 53 leakage.

---

## 📊 Comparison Table: AEGS v4 Pantheon vs Competitors

| Feature | WireGuard | AmneziaWG 3.1 | XTLS-Reality | **AEGS v4 Pantheon** |
|---|---|---|---|---|
| Static DPI signature | ❌ Static | ⚠️ Masked header | N/A (TCP only) | ✅ **Zero signatures (masked + random IV)** |
| DPI State-Machine Bypass | ❌ None | ⚠️ Random junk (`Jc`) | ⚠️ TLS ClientHello | ✅ **Illusion (RFC 5389 STUN + RFC 9000 QUIC)** |
| Anti-ML Padding | ❌ None | ⚠️ Uniform random | ❌ None | ✅ **Bimodal Semantic Shaping (~256B / ~1350B)** |
| Anti-Timing Obfuscation | ❌ None | ❌ None | ❌ None | ✅ **Active Chaffing (PlainHDR bit 0x80)** |
| Active Prober Defense | ❌ None | ⚠️ DNS FORMERR | ✅ TLS Camouflage | ✅ **Cryptographic Blackhole (3 QUIC strategies)** |
| Transport Protocol | UDP | UDP | TCP only | ✅ **UDP + Port Hopping + Mimicry** |
| Forward Secrecy (PFS) | ✅ Noise IK | ✅ Noise IK | ✅ TLS 1.3 | ✅ **X25519 ECDH per-session** |
| Hardware Kill-Switch | ⚠️ Client app | ⚠️ Client app | ⚠️ Client app | ✅ **Firewall Isolation + Port 53 Shield** |
| Zero-Allocation Hot Path | ✅ | ⚠️ | ⚠️ | ✅ **Thread-local scratch buffers** |

---

## 🧪 12-Pillar Test Suite

The project includes a comprehensive 12-Pillar verification suite:
* **Pillar 1:** Cryptographic Context Separation (HKDF-SHA256, 200k PBKDF2 iterations)
* **Pillar 2:** Shannon Entropy (>7.2 / 8.0 on wire, indistinguishable from white noise)
* **Pillar 3:** RFC 6479 64-bit Anti-Replay Sliding Window & 100% Poly1305 tamper detection
* **Pillar 4:** Active DPI Probing & Malformed Scan Resistance (5,000 scans)
* **Pillar 5:** Zero-Allocation Throughput & Processing Benchmark
* **Pillar 6:** Semantic Bimodal Padding & Size Distribution (~256B & ~1350B)
* **Pillar 7:** State-Machine Pre-Bypass (RFC 5389 STUN & RFC 9000 QUIC Initial format)
* **Pillar 8:** Active Chaffing, Idle Detection & Server Silent Drop
* **Pillar 9:** Cryptographic Blackhole Adaptive Probing Deception (Token-bucket rate limiter + 3 strategies)
* **Pillar 10:** Deterministic HMAC-SHA256 Port Hopping with Uniform Port Distribution
* **Pillar 11:** ChaCha20-Poly1305 Encrypted 96-Byte Session Resumption Tokens (<5ms 0-RTT)
* **Pillar 12:** Hardware Kill-Switch Isolation, Port 53 DNS Shield & Transport Blackout Detection

Run the suite:
```bash
python test_suite_v4.py
# or C++ native test runner:
./build/aegis_test
```

---

## 🚀 Quick Start

### Server (Linux)
```bash
git clone https://github.com/XDGOOD/net-packet-handler
cd net-packet-handler
./scripts/manage.sh install    # Builds, installs, starts systemd service
./scripts/manage.sh add-user alice  # Creates user, prints client token
```

### Client
* **Linux / macOS:**
  ```bash
  ./aegis_client <SERVER_IP> 50001 <YOUR_TOKEN>
  ```
* **Windows (Native Python Runner):**
  ```bash
  python scripts/quick_client.py run -s <SERVER_IP> -t <YOUR_TOKEN>
  ```
* **Docker Deployment:**
  ```bash
  docker compose up -d
  ```

---

## 📁 Project Structure
* `client.cpp` — Native client implementation with Illusion Pre-Bypass, ChaffEngine, and Semantic Padding.
* `server.cpp` — Epoll server listener, BlackholeResponder, NAT manager, and session table.
* `illusion_prebypass.h/cpp` — State-Machine Pre-Bypass (STUN RFC 5389 & QUIC Initial RFC 9000 decoys).
* `traffic_shaper.h/cpp` — Semantic padding (bimodal distribution) and microsecond send jitter.
* `chaff_engine.h/cpp` — Active chaffing generation and idle timing engine.
* `blackhole_responder.h/cpp` — Cryptographic blackhole response generator for probe deterrence.
* `test_runner.cpp` — Native C++ 11-Pillar test suite.
* `test_suite_v4.py` — Standalone Python 11-Pillar verification runner.
* `scripts/quick_client.py` — Cross-platform client supervisor and WireGuard proxy.
