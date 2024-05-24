#include "util.h"
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>

size_t serialize_mpz(int fd, mpz_t x)
{
    size_t nB;
    unsigned char* buf = Z2BYTES(NULL, &nB, x);
    if (!buf) {
        nB = 1;
        buf = malloc(1);
        *buf = 0;
    }
    assert(nB < 1LU << 32); 
    LE(nB);
    xwrite(fd, &nB_le, 4);
    xwrite(fd, buf, nB);
    free(buf);
    return nB + 4;
}

int deserialize_mpz(mpz_t x, int fd)
{
    uint32_t nB_le;
    xread(fd, &nB_le, 4);
    size_t nB = le32toh(nB_le);
    if (nB > MPZ_MAX_LEN) return -1;
    unsigned char* buf = malloc(nB);
    xread(fd, buf, nB);
    BYTES2Z(x, buf, nB);
    free(buf);
    return 0;
}

void xread(int fd, void *buf, size_t nBytes)
{
    do {
        ssize_t n = read(fd, buf, nBytes);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EWOULDBLOCK) continue;
        if (n < 0) perror("read"), abort();
        buf = (char *)buf + n;
        nBytes -= n;
    } while (nBytes);
}

void xwrite(int fd, const void *buf, size_t nBytes)
{
    do {
        ssize_t n = write(fd, buf, nBytes);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && errno == EWOULDBLOCK) continue;
        if (n < 0) perror("write"), abort();
        buf = (const char *)buf + n;
        nBytes -= n;
    } while (nBytes);
}
