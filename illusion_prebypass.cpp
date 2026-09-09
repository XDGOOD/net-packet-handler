#include "illusion_prebypass.h"
#include <sys/socket.h>
#include <unistd.h>
#include <random>
#include <chrono>
#include <cstring>
#include <openssl/rand.h>

std::vector<uint8_t> IllusionPreBypass::generate_stun_binding() {
    std::vector<uint8_t> pkt(20, 0);
    // 0x0001 Binding Request
    pkt[0] = 0x00;
    pkt[1] = 0x01;
    // Length: 0x0000
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    // Magic Cookie: 0x2112A442
    pkt[4] = 0x21;
    pkt[5] = 0x12;
    pkt[6] = 0xA4;
    pkt[7] = 0x42;
    // Transaction ID: 12 random bytes
    RAND_bytes(&pkt[8], 12);
    return pkt;
}

std::vector<uint8_t> IllusionPreBypass::generate_quic_initial() {
    // Need at least 1200 bytes
    std::vector<uint8_t> pkt(1200, 0);
    // 0xC3
    pkt[0] = 0xC3;
    // Version 1
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4] = 0x01;
    
    // DCID length 8
    pkt[5] = 8;
    RAND_bytes(&pkt[6], 8);
    // SCID length 8
    pkt[14] = 8;
    RAND_bytes(&pkt[15], 8);
    
    // Token length = 0
    pkt[23] = 0;
    // Length (varint, approx 1170 bytes) -> 0x44 0x92 (1170)
    pkt[24] = 0x44;
    pkt[25] = 0x92;
    
    // Packet Number 4 bytes
    RAND_bytes(&pkt[26], 4);
    
    // Payload
    RAND_bytes(&pkt[30], 1170);
    return pkt;
}

void IllusionPreBypass::send_illusion_sequence(int fd, const struct sockaddr_in& server_addr, const uint8_t* session_seed) {
    std::mt19937 rng(std::chrono::steady_clock::now().time_since_epoch().count());
    std::uniform_int_distribution<int> count_dist(1, 3);
    int count = count_dist(rng);

    for (int i = 0; i < count; ++i) {
        std::uniform_int_distribution<int> type_dist(0, 1);
        int type = type_dist(rng);
        std::vector<uint8_t> pkt;
        if (type == 0) {
            pkt = generate_stun_binding();
        } else {
            pkt = generate_quic_initial();
        }
        sendto(fd, (const char*)pkt.data(), pkt.size(), 0, (struct sockaddr*)&server_addr, sizeof(server_addr));
        // Small delay
        usleep(1000 * (10 + type_dist(rng)*40));
    }
}
