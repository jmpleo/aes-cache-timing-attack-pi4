/**
 * Original code from paper:
 *    Cache-timing attacks on AES
 * By:
 *    Daniel J. BERNSTEIN
 *    Department of Mathematics, Statistics, and Computer Science (M/C 249)
 *    The University of Illinois at Chicago
 *    Chicago, IL 60607–7045
 *    djb@cr.yp.to
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

double fisrtTimeMeanArray[16][256];
double firstTimeStdArray[16][256];
double secondTimeMeanArray[16][256];
double secondTimeStdArray[16][256];

double correlationCoefficients[256];
double squaredDeviationSum[256];
int correlationPositions[256];

void readTimings(void)
{
    int lines;

    int byteNumber, messageLen, byteValue;

    long long totalLocalPackets;

    double timingMean,
           timingMeanLocal,
           timingStd,
           timingStdLocal;

    for (lines = 0; lines < 4096; ++lines) {
        if (scanf("%d%d%d%lld%lf%lf%lf%lf",
                &byteNumber, &messageLen, &byteValue,
                &totalLocalPackets,
                &timingMeanLocal,
                &timingStdLocal,
                &timingMean,
                &timingStd) != 8) {
            exit(100);
        }

        byteNumber &= 15;
        byteValue &= 255;

        fisrtTimeMeanArray[byteNumber][byteValue] = timingMean;
        firstTimeStdArray[byteNumber][byteValue] = timingStd;
    }

    for (; lines < 8192; ++lines) {
        if (scanf("%d%d%d%lld%lf%lf%lf%lf",
                &byteNumber, &messageLen, &byteValue,
                &totalLocalPackets,
                &timingMeanLocal,
                &timingStdLocal,
                &timingMean,
                &timingStd) != 8) {
            exit(100);
        }
        byteNumber &= 15;
        byteValue &= 255;

        secondTimeMeanArray[byteNumber][byteValue] = timingMean;
        secondTimeStdArray[byteNumber][byteValue] = timingStd;
    }
}


int correlationPositionsCmp(const void *v1, const void *v2)
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

void rangeKeyValue(void)
{
    int byteNumber, byteValue, i, numCorrelated;
    double z;

    for (byteNumber = 0; byteNumber < 16; ++byteNumber) {
        for (i = 0; i < 256; ++i) {
            correlationCoefficients[i] = squaredDeviationSum[i] = 0;
            correlationPositions[i] = i;

            for (byteValue = 0; byteValue < 256; ++byteValue) {

                correlationCoefficients[i] += (
                    fisrtTimeMeanArray[byteNumber][byteValue] * secondTimeMeanArray[byteNumber][i ^ byteValue]
                );

                z = firstTimeStdArray[byteNumber][byteValue] * secondTimeMeanArray[byteNumber][i ^ byteValue];
                squaredDeviationSum[i] += z * z;

                z = fisrtTimeMeanArray[byteNumber][byteValue] * secondTimeStdArray[byteNumber][i ^ byteValue];
                squaredDeviationSum[i] += z * z;
            }
        }

        qsort(correlationPositions, 256, sizeof(int), correlationPositionsCmp);
        numCorrelated = 0;

        for (i = 0; i < 256; ++i) {
            if (correlationCoefficients[correlationPositions[0]]
                    - correlationCoefficients[correlationPositions[i]]
                        < 10 * sqrt(squaredDeviationSum[correlationPositions[i]])) {
                ++numCorrelated;
            }
        }

        printf("%3d %2d", numCorrelated, byteNumber);

        for (i = 0; i < 256; ++i) {
            if (correlationCoefficients[correlationPositions[0]]
                    - correlationCoefficients[correlationPositions[i]]
                        < 10 * sqrt(squaredDeviationSum[correlationPositions[i]])) {
                printf(" %02x", correlationPositions[i]);
            }
        }

        printf("\n");
    }
}

int main()
{
    readTimings();
    rangeKeyValue();
    return 0;
}

