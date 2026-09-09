# AEGS v3 Protocol Specification

## 1. Introduction
- Problem: stateful DPI systems (ТСПУ, GFW, Cloudflare Magic Firewall) identify VPN protocols by static signatures
- Solution: AEGS v3 — transport protocol with per-packet randomized wire format
- Scope: UDP transport, IPv4 tunneling, multi-user

## 2. Terminology
- Token: 256-bit pre-shared secret (user credential)
- KeyID: first 8 bytes of SHA-256(Token)
- MasterKey: PBKDF2-HMAC-SHA256(Token, KeyID, 200000 iterations, 32 bytes)
- MaskKey: HKDF-Expand(MasterKey, "aegis-v2-header-mask", 32)
- PayloadKey: HKDF-Expand(MasterKey, "aegis-v2-payload-key", 32)
- Session: active connection identified by KeyID and client UDP endpoint
- SessionKey: ephemeral per-session Curve25519 ECDH-derived key (provides PFS)

## 3. Cryptographic Primitives
- Symmetric encryption: ChaCha20-Poly1305 (RFC 8439), 256-bit key, 96-bit nonce
- Key derivation: PBKDF2-HMAC-SHA256 + HKDF-SHA256 (RFC 5869)
- Asymmetric: X25519 (Curve25519 ECDH, RFC 7748)
- MAC: HMAC-SHA256 truncated to 16 bytes
- CSPRNG: OpenSSL RAND_bytes

## 4. Session Establishment (Handshake)

### 4.1 HANDSHAKE_INIT (Client → Server)
Exact byte layout (72 bytes):
```
Offset  Len  Field
0       1    Type = 0x01
1       7    Reserved = 0x00...
8       8    KeyID = SHA-256(Token)[:8]
16      32   ClientEphemeralPublicKey (X25519)
48      8    Timestamp_ms (uint64 big-endian, Unix ms)
56      16   MAC = HMAC-SHA256(MasterKey, bytes[0:56])[:16]
```

Security properties:
- MAC authenticates that the sender knows the per-user Token (via MasterKey)
- Timestamp within ±30 seconds (anti-replay)
- Server rejects duplicate timestamps (sliding window, bounded at 100k entries)
- Pending handshake states bounded at 1024 with 30-second TTL (DoS protection)

### 4.2 HANDSHAKE_RESP (Server → Client)
Byte layout (80 bytes):
```
Offset  Len  Field
0       1    Type = 0x02
1       7    Reserved = 0x00...
8       8    SessionID (random uint64)
16      32   ServerEphemeralPublicKey (X25519)
48      16   EncryptedConfig = ChaCha20-Poly1305({AssignedIP[4], MTU[2], zeros[10]})
64      16   AEAD_Tag (Poly1305 authentication tag for EncryptedConfig)
```

### 4.3 Session Key Derivation
```
SharedSecret = X25519(ClientEphPri, ServerEphPub)
C2S_Key = HKDF(SharedSecret, salt=KeyID, info="aegs-c2s", len=32)
S2C_Key = HKDF(SharedSecret, salt=KeyID, info="aegs-s2c", len=32)
```
Provides Perfect Forward Secrecy: session keys are ephemeral and not recoverable from Token.
No fallback to pre-shared keys — handshake failure results in explicit abort with retry.

## 5. Data Packet Format

### 5.1 Wire Packet Structure
```
+------------------+------------------+------------ +----------+------------------+
| HDR_IV (12)      | MASKED_HDR (16)  | JUNK (0-N)  | NONCE(12)| CIPHERTEXT (var) |
+------------------+------------------+-------------+----------+------------------+
```

All fields in order:
- `HDR_IV` (12 bytes): random per-packet IV for header masking
- `MASKED_HDR` (16 bytes): ChaCha20(PlainHDR, MaskKey, 0x00000000||HDR_IV)
- `JUNK` (0-N bytes): random bytes, length encoded in PlainHDR
- `AEAD_NONCE` (12 bytes): first 8 bytes = tx_seq (little-endian uint64), last 4 = random
- `CIPHERTEXT`: ChaCha20-Poly1305(FRAME, SessionKey|PayloadKey, AEAD_NONCE)

### 5.2 PlainHDR Structure (16 bytes, before masking)
```
Offset  Len  Field
0       8    KeyID
8       2    JunkLen (big-endian uint16)
10      2    Reserved = 0x0000
12      4    VER_MAGIC = 0x41473201 ("AG2\x01")
```

VER_MAGIC is NEVER visible on wire (always masked with per-packet ChaCha20 stream).

### 5.3 Frame Structure (inside AEAD)
```
Offset  Len   Field
0       2     PayloadLen (big-endian uint16)
2       P     IP Packet (raw IPv4)
2+P     R     Random padding (R = secure_random(32..256))
```

## 6. Anti-Replay
64-bit sliding window per RFC 6479:
- Window size: 64 packets
- Reject: seq == 0, seq older than window, seq already seen
- Accept: new seq (advance window), out-of-order within window

## 7. IP Address Management
- Server pool: 10.8.0.2 – 10.8.0.254 (253 concurrent clients)
- Server address: 10.8.0.1/24 on aegs0
- Assignment: during HANDSHAKE_RESP, in EncryptedConfig field
- Release: on session idle timeout (180 seconds)

## 8. DPI Evasion Properties (AEGS v4 Pantheon)

### 8.1 State-Machine Pre-Bypass ("AEGS Illusion")
Before sending `HANDSHAKE_INIT`, the client transmits 1-3 decoy packets that perfectly
mimic standard STUN Binding Requests (RFC 5389) or QUIC Initial packets (RFC 9000).

**Effect:** DPI state machines classify the flow as `App: STUN / WebRTC` or `App: HTTP/3`
and stop deep inspection. The real cryptographic handshake proceeds under this cover identity.

Module: `illusion_prebypass.h/cpp`

### 8.2 Semantic Padding ("Bimodal Shaping" — Anti-ML)
Replaces uniform random padding (32-256 bytes) with intelligent bimodal shaping:
- Small packets (≤200 B) → padded to ~256 B (QUIC ACK profile, ±16 B jitter)
- Large packets (>200 B) → padded to ~1350 B (full MTU QUIC frame, ±32 B jitter)
- 5% probability of medium packets (512-768 B) to prevent fingerprinting the bimodal itself

**Effect:** ML classifiers see a packet-size distribution indistinguishable from
YouTube / QUIC browsing traffic. Configured via `AEGS_SEMANTIC_PADDING=1`.

Module: `traffic_shaper.h/cpp` (`semantic_pad()` method)

### 8.3 Active Chaffing (Anti-Timing Analysis)
During idle periods (>500 ms since last real packet), the client generates chaff packets
at random 50-200 ms intervals. Chaff packets use the standard AEGS wire format with
bit `0x80` set in PlainHDR byte 10 (Reserved field). The server authenticates and then
silently drops them without forwarding to TUN.

**Effect:** To an observer, the tunnel looks like a continuous WebRTC voice call with
constant packet flow, masking real user activity timing patterns.

Module: `chaff_engine.h/cpp`

### 8.4 Cryptographic Blackhole (Anti Active Probing)
When receiving invalid probe packets, the server responds with realistic QUIC packets
derived from the probe's own entropy:
- QUIC Version Negotiation (60%) — echoes probe CIDs, offers versions 1 + draft-32
- QUIC Retry (20%) — asks prober to retry with a token
- QUIC Connection Close (20%) — reports PROTOCOL_VIOLATION

**Effect:** Active scanners conclude this is an ordinary QUIC server and de-list the IP.
Rate-limited to 5 responses/sec per source IP.

Module: `blackhole_responder.h/cpp`

### 8.5 Summary Table
| Property | How achieved |
|---|---|
| Defeats DPI state machines | Illusion pre-bypass (fake STUN/QUIC before handshake) |
| Defeats ML classifiers | Bimodal semantic padding (YouTube-like distribution) |
| Defeats timing analysis | Active chaffing (constant packet flow during idle) |
| Defeats active probing | Cryptographic blackhole (varied QUIC responses) |
| No static byte signature | VER_MAGIC always masked; first 12 bytes are random IV |
| Looks like random UDP | All observable bytes are pseudorandom |
| Variable length | Semantic padding + random junk per packet |
| No timing pattern | Chaff engine + epoll-based, no sleep() in hot path |

## 11. Port Hopping (Active DPI Evasion)

AEGS v4 rotates the active UDP port every `hop_interval` seconds using HMAC-SHA256:

```
epoch = floor(time() / hop_interval)
hmac = HMAC-SHA256(session_key, epoch_be64)
port = base_port + (le32(hmac[0:4]) % port_count)
```

**Properties:**
- Server binds all ports simultaneously (base_port to base_port + count - 1)
- Client deterministically predicts the active port
- Different sessions hop on different schedules (key-dependent)
- Boundary window: client tries both current and next epoch port during transitions

**Wire format unchanged** — port hopping is purely at the transport layer.

## 12. Session Resumption (Zero-RTT Reconnect)

After successful ECDH handshake, server issues a **ResumptionToken** (96 bytes):

| Field | Size | Description |
|-------|------|-------------|
| nonce | 32 B | Random nonce |
| ciphertext | 32 B | Encrypted: session_id(8) + ip(4) + expiry_ms(8) + zeros(12) |
| tag | 16 B | Poly1305 AEAD tag |
| reserved | 16 B | Zero-padded, future use |

**Encryption:** ChaCha20-Poly1305, key derived via HKDF(master_key, "aegs-v4-resumption-key")

**Protocol flow:**
1. Client sends `RESUME` packet: `0x04 || token[96]` (97 bytes)
2. Server verifies token, restores session state
3. Server issues new token for next reconnect
4. Reconnect completes in <5ms (vs ~1s full handshake)

**Security:**
- Anti-replay: server tracks used nonces
- Expiry: 3-minute TTL
- AEAD authentication prevents forgery

## 13. Security Considerations
- Token brute-force: 200,000 PBKDF2 iterations (~1s on modern CPU)
- DoS: rate limiter (5 responses/sec per IP), IP banning after 10 weight points
- Replay: RFC 6479 64-bit window
- Forward secrecy: ephemeral X25519 per session
- Memory safety: ASan/UBSan verified, zero heap allocs in hot path
- Chaff MAC verification: chaff packets are fully authenticated before dropping

## 10. Comparison with Related Protocols
| Feature | WireGuard | AmneziaWG 3.1 | XTLS-Reality | AEGS v4 Pantheon |
|---|---|---|---|---|
| Static handshake signature | Yes | Masked | N/A (TCP) | Masked + Illusion decoys |
| Padding | None | Uniform random (Jc) | None | Bimodal semantic (anti-ML) |
| Timing obfuscation | None | None | None | Active chaffing |
| Active probe resistance | None | DNS FORMERR | TLS camouflage | QUIC blackhole (3 strategies) |
| Forward secrecy | Yes | Yes | Yes | Yes (X25519 per session) |
| Protocol | UDP | UDP | TCP | UDP |

