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
#include <openssl/aes.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

/* Returns a timestamp based on virtual CPU cycle count */
/*
inline unsigned long long timestamp(void)
{
    // asm volatile("mrs %0, cntvct_el0" : "=r"(cc));
    //asm volatile("rdtsc" : "=A"(cc));

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t cc = ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    return cc;

    //unsigned int low, high;
    //asm volatile("rdtsc" : "=a" (low), "=d" (high));
    //return ((unsigned long long)high << 32) | low;
}
*/

static inline uint64_t timestamp()
{
    uint64_t cycles;
    __asm__ volatile("rdtsc" : "=A"(cycles));
    return cycles;
}

unsigned char key[16];
AES_KEY expandedKey;
unsigned char zerosPlainBlock[16];
unsigned char cipherBlock[16];

void handle(char out[48], char in[], int len)
{
    unsigned char workarea[len * 3];
    int i;

    // 0 0 0 0 ... 0
    for (i = 0; i < 48; ++i) {
        out[i] = 0;
    }

    // 0 0 0 ... 0 timestamp 0 0 0 0
    *(uint64_t*)(out + 32) = timestamp();

    if (len < 16) {
        return;
    }

    // in[0] in[1] ... in[16] 0 0 0 0 ... 0 timestamp_start 0 0 0 0
    for (i = 0; i < 16; ++i) {
        out[i] = in[i];
    }

    // workarea = in[16] in[17] ... in [len - 1] ....
    //for (i = 16; i < len; ++i) {
    //    workarea[i] = in[i];
    //}


    AES_encrypt((unsigned char *)in, workarea, &expandedKey);
    /* a real server would now check AES-based authenticator, */
    /* process legitimate packets, and generate useful output */

    // in[0] in[1] ... in[16] out[0] out[1] ... out[15] timestamp_start 0 0 0 0
    for (i = 0; i < 16; ++i) {
        out[16 + i] = cipherBlock[i];
    }

    // in[0] in[1] ... in[16] out[0] out[1] ... out[15] timestamp_start timestamp_end
    *(uint64_t*)(out + 40) = timestamp();
}

struct sockaddr_in server;
struct sockaddr_in client;
socklen_t clientlen;
int s;
char in[1537];
int r;
char out[48];

int main(int argc, char **argv)
{
    printf("Starting server\n");

    if (read(0, key, sizeof key) < sizeof key) {
        fprintf(stderr, "Failed to read key\n");
        return 111;
    }

    AES_set_encrypt_key(key, 128, &expandedKey);
    AES_encrypt(zerosPlainBlock, cipherBlock, &expandedKey);

    if (!argv[1]) {
        return 100;
    }

    if (!inet_aton(argv[1], &server.sin_addr)) {
        return 100;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(10000);

    s = socket(AF_INET, SOCK_DGRAM, 0);

    if (s == -1) {
        fprintf(stderr, "Failed to create socket\n");
        return 111;
    }

    if (bind(s, (struct sockaddr *)&server, sizeof server) == -1) {
        fprintf(stderr, "Failed to bind\n");
        return 111;
    }

    for (;;) {

        //fprintf(stdout, "listen...\n");
        clientlen = sizeof client;

        r = recvfrom(
            s, in, sizeof in, 0, (struct sockaddr *)&client, &clientlen);

        if (r < 16) {
            continue;
        }

        if (r >= sizeof in) {
            continue;
        }

        //fprintf(stdout, "recived %i \n", r);
        handle(out, in, r);
        sendto(s, out, 48, 0, (struct sockaddr *)&client, clientlen);
    }
}
