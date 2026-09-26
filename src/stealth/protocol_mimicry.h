#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Protocol Mimicry (Component 3: DPI bypass)
// ==============================================================================
// Wraps outbound UDP packets with a dynamic QUIC Initial or Version Negotiation
// header so that stateless DPI engines classify the flow as benign QUIC traffic.
//
// Complies with RFC 9000 & RFC 9369:
// - Eliminates static 6-byte signature (0xC0 0x00 0x00 0x00 0x01 0x08).
// - Randomizes Connection IDs (DCID: 8 bytes, SCID: 8 bytes).
// - Masks low 4 bits of the header byte (simulating wire header protection).
// - Supports dynamic version negotiation and dynamic QUIC versions (v1, v2, draft-29, draft-32).
//
// RFC 9000 Long Header layout (24 bytes):
//   byte 0:       0xC0 | (random & 0x0F)   — Long Header, Initial type, protected low bits
//                 (or 0x80 | (random & 0x7F) for Version Negotiation)
//   bytes 1-4:    Dynamic QUIC version (v1, v2, drafts, or 0x00000000 for version neg)
//   byte 5:       0x08                     — DCID Length = 8
//   bytes 6-13:   8 bytes DCID             — Randomized / session-derived Connection ID
//   byte 14:      0x08                     — SCID Length = 8
//   bytes 15-22:  8 bytes SCID             — Randomized Connection ID
//   byte 23:      0x00                     — Token Length = 0
//
// The real AEGS payload follows immediately after the mimicry header.
// On the receive side call unwrap_offset() to skip the header.
// ==============================================================================

#include <cstddef>
#include <cstdint>

class ProtocolMimicry {
public:
    enum class Mode {
        NONE,                // No mimicry — pass through unchanged
        QUIC_INITIAL,        // Prepend RFC 9000 QUIC Initial header with randomized CIDs/version
        HTTP3,               // Prepend RFC 9000 QUIC/HTTP3 header
        VERSION_NEGOTIATION  // Prepend RFC 9000 QUIC Version Negotiation header
    };

    // Supported QUIC versions per RFC 9000 / RFC 9369
    static constexpr uint32_t kQuicVersion1 = 0x00000001; // RFC 9000 QUIC v1
    static constexpr uint32_t kQuicVersion2 = 0x6B3343CF; // RFC 9369 QUIC v2
    static constexpr uint32_t kQuicDraft29  = 0xFF00001D; // draft-29
    static constexpr uint32_t kQuicDraft32  = 0xFF000020; // draft-32
    static constexpr uint32_t kQuicVerNeg   = 0x00000000; // RFC 9000 Version Negotiation

    static constexpr size_t kQuicHeaderSize = 24;

    // Checks whether an incoming buffer contains a valid RFC 9000 QUIC mimicry header
    // Supports dynamic CID lengths (4..20 bytes) to prevent fingerprinting
    static inline bool is_quic_mimicry(const uint8_t* buf, size_t len) noexcept {
        if (!buf || len < 12) return false;
        uint8_t b0 = buf[0];
        if ((b0 & 0x80) == 0) return false; // Must be Long Header

        uint32_t version = (static_cast<uint32_t>(buf[1]) << 24) |
                           (static_cast<uint32_t>(buf[2]) << 16) |
                           (static_cast<uint32_t>(buf[3]) << 8)  |
                            static_cast<uint32_t>(buf[4]);

        bool valid_version = (version == kQuicVersion1 || version == kQuicVersion2 ||
                              version == kQuicDraft29  || version == kQuicDraft32  ||
                              version == kQuicVerNeg);
        if (!valid_version) return false;

        uint8_t dcid_len = buf[5];
        if (dcid_len > 20) return false;
        size_t scid_offset = 6 + dcid_len;
        if (scid_offset >= len) return false;

        uint8_t scid_len = buf[scid_offset];
        if (scid_len > 20) return false;

        size_t token_offset = scid_offset + 1 + scid_len;
        if (token_offset > len) return false;

        return true;
    }

    // In-place zero-copy unwrap: advances pointer past dynamic RFC 9000 QUIC header and reduces len
    static inline bool strip_quic_mimicry(const uint8_t*& buf, size_t& len) noexcept {
        if (!buf || len < 12) return false;
        uint8_t b0 = buf[0];
        if ((b0 & 0x80) == 0) return false; // Long Header

        uint32_t version = (static_cast<uint32_t>(buf[1]) << 24) |
                           (static_cast<uint32_t>(buf[2]) << 16) |
                           (static_cast<uint32_t>(buf[3]) << 8)  |
                            static_cast<uint32_t>(buf[4]);

        bool valid_version = (version == kQuicVersion1 || version == kQuicVersion2 ||
                              version == kQuicDraft29  || version == kQuicDraft32  ||
                              version == kQuicVerNeg);
        if (!valid_version) return false;

        uint8_t dcid_len = buf[5];
        if (dcid_len > 20) return false;
        size_t scid_offset = 6 + dcid_len;
        if (scid_offset >= len) return false;

        uint8_t scid_len = buf[scid_offset];
        if (scid_len > 20) return false;

        size_t token_offset = scid_offset + 1 + scid_len;
        if (token_offset > len) return false;

        size_t hdr_len = token_offset;
        if (version != kQuicVerNeg) {
            if (token_offset >= len) return false;
            uint8_t t0 = buf[token_offset];
            size_t token_val_len = 0;
            size_t varint_len = 1;
            if ((t0 & 0xC0) == 0x00) {
                token_val_len = t0;
                varint_len = 1;
            } else if ((t0 & 0xC0) == 0x40) {
                if (token_offset + 2 > len) return false;
                token_val_len = ((t0 & 0x3F) << 8) | buf[token_offset + 1];
                varint_len = 2;
            }
            hdr_len = token_offset + varint_len + token_val_len;
        }

        if (hdr_len >= len) return false;
        buf += hdr_len;
        len -= hdr_len;
        return true;
    }

    static inline bool strip_quic_mimicry(uint8_t*& buf, size_t& len) noexcept {
        const uint8_t* cbuf = buf;
        if (strip_quic_mimicry(cbuf, len)) {
            buf = const_cast<uint8_t*>(cbuf);
            return true;
        }
        return false;
    }

    // Checks whether an incoming buffer contains a TLS 1.3 Reality ECH wrapper
    // Zero static strings (eliminating "AEG1" DPI pattern-matching vector)
    static inline bool is_tls_reality_mimicry(const uint8_t* buf, size_t len) noexcept {
        if (!buf || len < 45 || buf[0] != 0x16) return false;
        for (size_t i = 5; i + 10 <= len; ++i) {
            if (buf[i] == 0xFE && buf[i + 1] == 0x0D) {
                size_t ext_len = (static_cast<size_t>(buf[i + 2]) << 8) | buf[i + 3];
                if (ext_len >= 6 && i + 4 + 6 <= len) {
                    // Check ECH outer header: outer(0x00), KDF HKDF-SHA256 (0x0020), AEAD (0x0001 or 0x0003), config_id
                    if (buf[i + 4] == 0x00 && buf[i + 5] == 0x00 && buf[i + 6] == 0x20) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    // In-place zero-copy unwrap for TLS 1.3 Reality ECH without static wire signatures
    static inline bool strip_tls_reality_mimicry(const uint8_t*& buf, size_t& len) noexcept {
        if (!buf || len < 45 || buf[0] != 0x16) return false;
        for (size_t i = 5; i + 10 <= len; ++i) {
            if (buf[i] == 0xFE && buf[i + 1] == 0x0D) {
                size_t ext_len = (static_cast<size_t>(buf[i + 2]) << 8) | buf[i + 3];
                size_t ext_end = (i + 4 + ext_len < len) ? (i + 4 + ext_len) : len;
                if (ext_len >= 6 && i + 4 + 6 <= ext_end) {
                    if (buf[i + 4] == 0x00 && buf[i + 5] == 0x00 && buf[i + 6] == 0x20) {
                        // Standard payload offset right after ECH header (i + 10)
                        size_t payload_start = i + 10;
                        // Backward compatibility: skip legacy AEG1 magic if present
                        if (payload_start + 4 <= ext_end &&
                            buf[payload_start] == 'A' && buf[payload_start + 1] == 'E' &&
                            buf[payload_start + 2] == 'G' && buf[payload_start + 3] == '1') {
                            payload_start += 4;
                        }
                        if (payload_start < ext_end) {
                            size_t payload_len = ext_end - payload_start;
                            buf += payload_start;
                            len = payload_len;
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    static inline bool strip_tls_reality_mimicry(uint8_t*& buf, size_t& len) noexcept {
        const uint8_t* cbuf = buf;
        if (strip_tls_reality_mimicry(cbuf, len)) {
            buf = const_cast<uint8_t*>(cbuf);
            return true;
        }
        return false;
    }


    explicit ProtocolMimicry(Mode mode = Mode::NONE, uint32_t quic_version = 0) noexcept;

    // Direct helper to wrap a buffer with an RFC 9000 QUIC Initial header with randomized
    // Connection IDs (DCID, SCID) and dynamic version selection.
    // session_seed: optional 2-byte seed to mix into DCID; if nullptr, fully randomized.
    // quic_version: target version, or 0 for dynamic version selection.
    static size_t wrap_quic_initial(uint8_t*       buf,
                                    size_t         data_len,
                                    size_t         buf_capacity,
                                    const uint8_t  session_seed[2] = nullptr,
                                    uint32_t       quic_version = 0) noexcept;


    // Prepend the mimicry header in-place.
    // The caller MUST ensure buf_capacity >= data_len + header_size_.
    // Data bytes [0..data_len) are shifted right by header_size_ bytes.
    // Returns new total packet length, or data_len if Mode::NONE.
    size_t wrap(uint8_t*       buf,
                size_t         data_len,
                size_t         buf_capacity,
                const uint8_t  session_seed[2] = nullptr) noexcept;

    // Returns the byte offset at which real AEGS data starts in an inbound packet.
    size_t unwrap_offset() const noexcept { return header_size_; }

    Mode     mode()         const noexcept { return mode_; }
    size_t   header_size()  const noexcept { return header_size_; }
    uint32_t quic_version() const noexcept { return quic_version_; }

    void set_mode(Mode mode) noexcept;
    void set_quic_version(uint32_t version) noexcept { quic_version_ = version; }

private:
    Mode     mode_;
    size_t   header_size_;  // 0 for NONE, 24 for QUIC_INITIAL / HTTP3 / VERSION_NEGOTIATION
    uint32_t quic_version_; // 0 = dynamic selection
};

// Global free function helper for wrap_quic_initial
inline size_t wrap_quic_initial(uint8_t*       buf,
                                size_t         data_len,
                                size_t         buf_capacity,
                                const uint8_t  session_seed[2] = nullptr,
                                uint32_t       quic_version = 0) noexcept {
    return ProtocolMimicry::wrap_quic_initial(buf, data_len, buf_capacity, session_seed, quic_version);
}
