// test_endian.c
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <stdio.h>
#include <endian.h>
#include <stdint.h>

uint64_t test_endian(void) { return htobe64(42); }

int main(void)
{
    printf("%lu\n", test_endian());
    return 0;
}