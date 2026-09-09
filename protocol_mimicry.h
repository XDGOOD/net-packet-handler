#pragma once
// ==============================================================================
// AEGS v4 "Pantheon" -- Protocol Mimicry (Component 3: DPI bypass)
// ==============================================================================
// Wraps outbound UDP packets with a fake QUIC Initial or HTTP/3 header so
// that stateless DPI engines classify the flow as benign QUIC traffic.
//
// QUIC Initial header layout (simplified, 8 bytes):
//   byte 0:    0xC0  — Long Header flag | QUIC Initial packet type
//   bytes 1-4: 0x00 0x00 0x00 0x01  — QUIC version 1 (RFC 9000)
//   byte 5:    0x08  — DCID Length = 8
//   bytes 6-7: 2 session-derived pseudo-random bytes (DCID prefix)
//
// The real AEGS payload follows immediately after the mimicry header.
// On the receive side call unwrap_offset() to skip the header.
// ==============================================================================

#include <cstddef>
#include <cstdint>

class ProtocolMimicry {
public:
    enum class Mode {
        NONE,         // No mimicry — pass through unchanged
        QUIC_INITIAL, // Prepend 8-byte fake QUIC Initial header
        HTTP3         // Prepend 8-byte fake QUIC/HTTP3 header (same layout)
    };

    explicit ProtocolMimicry(Mode mode = Mode::NONE) noexcept;

    // Prepend the mimicry header in-place.
    // The caller MUST ensure buf_capacity >= data_len + header_size_.
    // Data bytes [0..data_len) are shifted right by header_size_ bytes.
    // session_seed: 2 bytes used as the DCID pseudo-random prefix;
    //               pass nullptr to use 0x00 0x00 (e.g. for benchmarks).
    // Returns new total packet length, or data_len if Mode::NONE.
    size_t wrap(uint8_t*       buf,
                size_t         data_len,
                size_t         buf_capacity,
                const uint8_t  session_seed[2] = nullptr) noexcept;

    // Returns the byte offset at which real AEGS data starts in an inbound
    // packet. Caller should read: buf[unwrap_offset()..len).
    size_t unwrap_offset() const noexcept { return header_size_; }

    Mode   mode()        const noexcept { return mode_; }
    size_t header_size() const noexcept { return header_size_; }

private:
    Mode   mode_;
    size_t header_size_;  // 0 for NONE, 8 for QUIC_INITIAL / HTTP3
};
