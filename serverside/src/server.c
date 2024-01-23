/**
 * Original code from paper:
 *    Cache-timing attacks on AES
 * By:
 *    Daniel J. BERNSTEIN
 *    Department of Mathematics, Statistics, and Computer Science (M/C 249)
 *    The University of Illinois at Chicago
 *    Chicago, IL 60607–7045
 *    djb@cr.yp.to
 *
 */

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <openssl/aes.h>
#include <stdio.h>
#include <unistd.h>
//#include <time.h>
#include <string.h>

#include "../../simple-aes/aes.h"

#define PACKET_LEN 48
#define MAX_MESSLEN 2000

uint8_t key[16];
uint8_t* expandedKey;
uint8_t scrambledZero[16];

struct Packet {
    uint8_t nonce[16];  // 16
    uint8_t out[16]; // 16
    uint64_t timestampStart; // 8
    uint64_t timestampEnd;   // 8
}; // 48

void packetHandle(struct Packet *packet, char clientMessage[], int len);

inline uint64_t timestamp(void)
{
    uint32_t bottom, top;
    asm volatile ("rdtsc" : "=a"(bottom), "=d"(top));
    return ((uint64_t)top << 32) | bottom;
}

int main(int argc, char **argv)
{
    printf("Starting server\n");

    if (read(0, key, sizeof key) < sizeof key) {
        fprintf(stderr, "Failed to read key\n");
        return 111;
    }

    expandedKey = aes_init(sizeof key);
    aes_key_expansion(key, expandedKey);

    uint8_t zero[16] = {0};
    aes_cipher(zero, scrambledZero, expandedKey);

    if (!argv[1]) {
        fprintf(stderr, "Using: server <bind addr>\n");
        return 100;
    }

    struct sockaddr_in server;
    struct sockaddr_in client;

    if (!inet_aton(argv[1], &server.sin_addr)) {
        fprintf(stderr, "Failed parsing addr\n");
        return 100;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(10000);

    int s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s == -1) {
        fprintf(stderr, "Failed to create socket\n");
        return 111;
    }

    if (bind(s, (struct sockaddr *)&server, sizeof server) == -1) {
        fprintf(stderr, "Failed to bind\n");
        return 111;
    }

    struct Packet packet;
    char buffer[MAX_MESSLEN];
    socklen_t clientSockLen;
    int receivedPacketLen;

    for (;;) {

        clientSockLen = sizeof client;

        receivedPacketLen = recvfrom(
            s,
            buffer,
            sizeof buffer,
            0,
            (struct sockaddr *)&client,
            &clientSockLen
        );

        if (receivedPacketLen < sizeof packet.nonce || receivedPacketLen >= sizeof buffer) {
            continue;
        }

        packetHandle(&packet, buffer, receivedPacketLen);
        sendto(
            s,
            (uint8_t*)&packet,
            sizeof packet,
            0,
            (struct sockaddr *)&client,
            clientSockLen
        );
    }
}


void packetHandle(struct Packet *packet, char clientMessage[], int len)
{
    uint8_t workarea[len];

    if (len < sizeof packet->nonce) {
        return;
    }


    memcpy(packet->nonce, clientMessage, sizeof packet->nonce);
    memcpy(
        workarea + sizeof packet->nonce,
        clientMessage + sizeof packet->nonce,
        sizeof workarea - sizeof packet->nonce
    );

    packet->timestampStart = timestamp();
    aes_cipher(packet->nonce, workarea, expandedKey);
    packet->timestampEnd = timestamp();

    memcpy(packet->out, scrambledZero, sizeof packet->out);
}


