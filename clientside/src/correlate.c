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

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

double firstTimeArray[16][256];
double timeDeviationArray[16][256];
double secondTimeArray[16][256];
double standardDeviationArray[16][256];

double correlationCoefficients[256];
double squaredDeviationSum[256];
int sortedCorrelationPositions[256];

void readdata(void)
{
    int lines;
    int b;
    int size;
    int j;
    long long packets;
    double cycles;
    double deviation;
    double aboveaverage;
    double avdev;
    for (lines = 0; lines < 8192; ++lines) {
        if (scanf("%d%d%d%lld%lf%lf%lf%lf",
                    &j, &size, &b,
                    &packets,
                    &cycles,
                    &deviation,
                    &aboveaverage,
                    &avdev) != 8) {
            exit(100);
        }
        j &= 15;
        b &= 255;
        if (lines < 4096) {
            firstTimeArray[j][b] = aboveaverage;
            timeDeviationArray[j][b] = avdev;
        }
        else {
            secondTimeArray[j][b] = aboveaverage;
            standardDeviationArray[j][b] = avdev;
        }
    }
}


int sortedCorrelationPositionscmp(const void *v1, const void *v2)
{
    int *i1 = (int *)v1;
    int *i2 = (int *)v2;
    if (correlationCoefficients[255 & *i1] < correlationCoefficients[255 & *i2]) {
        return 1;
    }
    if (correlationCoefficients[255 & *i1] > correlationCoefficients[255 & *i2]) {
        return -1;
    }
    return 0;
}

void processdata(void)
{
    int b, i, j, numCorrelated;
    double z;
    for (b = 0; b < 16; ++b) {
        for (i = 0; i < 256; ++i) {
            correlationCoefficients[i] = squaredDeviationSum[i] = 0;
            sortedCorrelationPositions[i] = i;

            for (j = 0; j < 256; ++j) {
                correlationCoefficients[i] += firstTimeArray[b][j] * secondTimeArray[b][i ^ j];
                z = timeDeviationArray[b][j] * secondTimeArray[b][i ^ j];
                squaredDeviationSum[i] += z * z;
                z = firstTimeArray[b][j] * standardDeviationArray[b][i ^ j];
                squaredDeviationSum[i] += z * z;
            }
        }
        qsort(sortedCorrelationPositions, 256, sizeof(int), sortedCorrelationPositionscmp);
        numCorrelated = 0;
        for (i = 0; i < 256; ++i) {
            if (correlationCoefficients[sortedCorrelationPositions[0]]
                    - correlationCoefficients[sortedCorrelationPositions[i]]
                        < 10 * sqrt(squaredDeviationSum[sortedCorrelationPositions[i]])) {
                ++numCorrelated;
            }
        }
        printf("%3d %2d", numCorrelated, b);
        for (i = 0; i < 256; ++i) {
            if (correlationCoefficients[sortedCorrelationPositions[0]]
                    - correlationCoefficients[sortedCorrelationPositions[i]]
                        < 10 * sqrt(squaredDeviationSum[sortedCorrelationPositions[i]])) {
                printf(" %02x", sortedCorrelationPositions[i]);
            }
        }
        printf("\n");
    }
}

int main()
{
    readdata();
    processdata();
    return 0;
}
