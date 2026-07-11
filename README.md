# net-packet-handler
# Asynchronous UDP Transport PoC

A lightweight C++17 Proof-of-Concept for high-performance UDP packet framing and encapsulation using `epoll` and hardware-accelerated OpenSSL crypto. Designed to wrap and protect underlying datagram streams against heuristic analysis and active probing.

## Architecture Highlights
- **High Performance:** Non-blocking I/O event loop (`epoll` in Linux kernel space) with minimal memory allocations via pre-allocated static buffers.
- **Crypto & Framing:** OpenSSL EVP implementation of ChaCha20-Poly1305 with dynamic randomized padding to prevent packet-size timing attacks.
- **Active Probe Defense:** Integrated score-based penalty mechanism that drops invalid Magic-bytes and temporarily bans unauthorized scanners without CPU overhead.

## Files
- `server.cpp`: Core event loop, packet authenticator, and proxy handler.
- `client.cpp`: Local UDP proxy wrapper for payload encryption and padding.
- `CMakeLists.txt`: Build configuration (requires OpenSSL, Threads, SQLite3).
- `Dockerfile.aegis`: Containerized build environment for quick deployment.
