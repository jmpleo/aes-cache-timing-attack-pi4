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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

/* Returns a timestamp based on virtual CPU cycle count */
unsigned int timestamp(void)
{
    uint32_t cc;
   // asm volatile("mrs %0, cntvct_el0" : "=r"(cc));
    asm volatile("rdtsc" : "=A"(cc));
    return cc;
}

unsigned char key[16];
AES_KEY expandedKey;
unsigned char zerosPlainBlock[16];
unsigned char cipherBlock[16];

void handle(char out[40], char in[], int len)
{
    unsigned char workarea[len * 3];
    int i;

    // 0 0 0 0 ... 0
    for (i = 0; i < 40; ++i) {
        out[i] = 0;
    }

    // fprintf(stdout, "sizeof int %i \n", sizeof(int));
    // 0 0 0 ... 0 timestamp 0 0 0 0
    *(unsigned int *)(out + 32) = timestamp();

    if (len < 16) {
        return;
    }

    // in[0] in[1] ... in[16] 0 0 0 0 ... 0 timestamp_start 0 0 0 0
    for (i = 0; i < 16; ++i) {
        out[i] = in[i];
    }

    // workarea = in[16] in[17] ... in [len - 1] ....
    // for (i = 16; i < len; ++i) {
    //    workarea[i] = in[i];
    // }

    AES_encrypt(in, workarea, &expandedKey);
    /* a real server would now check AES-based authenticator, */
    /* process legitimate packets, and generate useful output */

    // in[0] in[1] ... in[16] C[0] C[1] ... C[15] timestamp_start 0 0 0 0
    for (i = 0; i < 16; ++i) {
        out[16 + i] = cipherBlock[i];
    }

    // in[0] in[1] ... in[16] C[0] C[1] ... C[15] timestamp_start timestamp_end
    *(unsigned int *)(out + 36) = timestamp();
}

struct sockaddr_in server;
struct sockaddr_in client;
socklen_t clientlen;
int s;
char in[1537];
int r;
char out[40];

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
        sendto(s, out, 40, 0, (struct sockaddr *)&client, clientlen);
    }
}
