// ==============================================================================
// AEGS v4 "Pantheon" -- Protocol Mimicry Implementation
// ==============================================================================
// wrap() performs a single memmove to make room for the header — no heap
// allocation occurs. The 8-byte header is written directly into the buffer.
// ==============================================================================

#include "protocol_mimicry.h"
#include <cstring>

// ---------------------------------------------------------------------------
// Static QUIC header template (mode-independent bytes 0-5)
// ---------------------------------------------------------------------------
//  0xC0 = 1100_0000b: Long Header (bit7=1), Fixed bit (bit6=1), Type=00 (Initial)
//  0x00 0x00 0x00 0x01 = QUIC version 1 (RFC 9000)
//  0x08 = DCID Length field = 8 bytes
static constexpr uint8_t kQuicHeaderTemplate[6] = {
    0xC0,                         // Long Header | Initial packet type
    0x00, 0x00, 0x00, 0x01,       // QUIC version 1
    0x08                          // DCID length = 8
};
// bytes [6..7] are filled from session_seed (DCID prefix bytes 0-1)

static constexpr size_t kHeaderSize = 8; // 6 template + 2 seed bytes

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
ProtocolMimicry::ProtocolMimicry(Mode mode) noexcept
    : mode_(mode),
      header_size_(mode == Mode::NONE ? 0 : kHeaderSize)
{}

// ---------------------------------------------------------------------------
// wrap()
// ---------------------------------------------------------------------------
size_t ProtocolMimicry::wrap(uint8_t*      buf,
                             size_t        data_len,
                             size_t        buf_capacity,
                             const uint8_t session_seed[2]) noexcept {
    if (mode_ == Mode::NONE)
        return data_len;

    // Ensure there is room for the header
    if (data_len + kHeaderSize > buf_capacity)
        return data_len; // Cannot prepend — return unchanged length as a safe fallback

    // Shift payload right to make room (overlapping move, so memmove)
    std::memmove(buf + kHeaderSize, buf, data_len);

    // Write QUIC/HTTP3 header (bytes 0-5 are always identical)
    std::memcpy(buf, kQuicHeaderTemplate, sizeof(kQuicHeaderTemplate));

    // Bytes 6-7: session-derived DCID prefix (looks like random DCID bytes)
    if (session_seed != nullptr) {
        buf[6] = session_seed[0];
        buf[7] = session_seed[1];
    } else {
        buf[6] = 0x00;
        buf[7] = 0x00;
    }

    return data_len + kHeaderSize;
}
