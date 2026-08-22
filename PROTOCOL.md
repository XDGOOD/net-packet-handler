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
56      16   MAC = HMAC-SHA256(ServerStaticPubKey, bytes[0:56])[:16]
```

Security properties:
- Timestamp within ±30 seconds (anti-replay)
- Server rejects duplicate timestamps

### 4.2 HANDSHAKE_RESP (Server → Client)
Byte layout (64 bytes):
```
Offset  Len  Field
0       1    Type = 0x02
1       7    Reserved = 0x00...
8       8    SessionID (random uint64)
16      32   ServerEphemeralPublicKey (X25519)
48      16   EncryptedConfig = ChaCha20({AssignedIP[4], MTU[2], zeros[10]})
```

### 4.3 Session Key Derivation
```
SharedSecret = X25519(ClientEphPri, ServerEphPub)
C2S_Key = HKDF(SharedSecret, salt=KeyID, info="aegs-c2s", len=32)
S2C_Key = HKDF(SharedSecret, salt=KeyID, info="aegs-s2c", len=32)
```
Provides Perfect Forward Secrecy: session keys are ephemeral and not recoverable from Token.

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

## 8. DPI Evasion Properties
| Property | How achieved |
|---|---|
| No static byte signature | VER_MAGIC always masked; first 12 bytes are random IV |
| Looks like random UDP | All observable bytes are pseudorandom |
| DNS fallback | Invalid packets get DNS FORMERR response |
| Variable length | Random junk padding per packet |
| No timing pattern | epoll-based, no sleep() in hot path |

## 9. Security Considerations
- Token brute-force: 200,000 PBKDF2 iterations (~1s on modern CPU)
- DoS: rate limiter (5 DNS responses/sec per IP), IP banning after 10 weight points
- Replay: RFC 6479 64-bit window
- Forward secrecy: ephemeral X25519 per session
- Memory safety: ASan/UBSan verified, zero heap allocs in hot path

## 10. Comparison with Related Protocols
WireGuard Noise provides strong cryptographic guarantees but has static handshake patterns that can be easily identified by DPI.
AmneziaWG obfuscation adds random padding and header masking to WireGuard, but AEGS v3 goes further by making all bytes pseudorandom and incorporating a DNS fallback mechanism for invalid packets, as well as zero heap allocs in the hot path.
