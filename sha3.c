/*
 * Copyright 2018 AtomMiner
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha3.h"
#include "miner.h"

//#define _ALGO_DEBUG

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) \
	(((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#endif

static const uint64_t keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

#define THETA0(r) bc##r = s[r] ^ s[r + 5] ^ s[r + 10] ^ s[r + 15] ^ s[r + 20];

#define THETA1(r, i1, i2) t = bc##i1 ^ SHA3_ROTL64(bc##i2, 1); \
for(j = 0; j < 25; j += 5) \
    s[j + r] ^= t;

static void
keccakf(uint64_t s[25])
{
    int i, j, round;
    uint64_t t, bc[5];
    uint64_t bc0, bc1, bc2, bc3, bc4;

    for(round = 0; round < 23; round++)
    {
        THETA0(0);
        THETA0(1);
        THETA0(2);
        THETA0(3);
        THETA0(4);

        THETA1(0, 4, 1);
        THETA1(1, 0, 2);
        THETA1(2, 1, 3);
        THETA1(3, 2, 4);
        THETA1(4, 3, 0);


        /* Rho Pi */
        t = s[1];
        for(i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc0 = s[j];
            s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
            t = bc0;
        }

        /* Chi */
        for(j = 0; j < 25; j += 5)
        {
            bc0 = s[j];
            bc1 = s[j + 1];
            bc2 = s[j + 2];
            bc3 = s[j + 3];
            bc4 = s[j + 4];

            s[j]     ^= (~bc1) & bc2;
            s[j + 1] ^= (~bc2) & bc3;
            s[j + 2] ^= (~bc3) & bc4;
            s[j + 3] ^= (~bc4) & bc0;
            s[j + 4] ^= (~bc0) & bc1;
        }

        /* Iota */
        s[0] ^= keccakf_rndc[round];
    }

    THETA0(0);
    THETA0(1);
    THETA0(2);
    THETA0(3);
    THETA0(4);

    THETA1(0, 4, 1);
    THETA1(1, 0, 2);
    THETA1(2, 1, 3);
    THETA1(3, 2, 4);
    THETA1(4, 3, 0);

    /* Rho Pi */
    t = s[1];
    for(i = 0; i < 24; i++) {
        j = keccakf_piln[i];
        bc0 = s[j];
        s[j] = SHA3_ROTL64(t, keccakf_rotc[i]);
        t = bc0;
    }

    s[0] ^= ((~s[1]) & s[2]) ^ keccakf_rndc[23];
    s[1] ^= (~s[2]) & s[3];
}

uint64_t swap64(uint64_t X) {
  uint64_t x = (uint64_t) X;
x = (x & 0x00000000FFFFFFFF) << 32 | (x & 0xFFFFFFFF00000000) >> 32;
x = (x & 0x0000FFFF0000FFFF) << 16 | (x & 0xFFFF0000FFFF0000) >> 16;
x = (x & 0x00FF00FF00FF00FF) << 8  | (x & 0xFF00FF00FF00FF00) >> 8;
return x;
}

void
sha3_Init256(void *priv)
{
    sha3_context *ctx = (sha3_context *) priv;
    memset(ctx, 0, sizeof(*ctx));
}

void const *sha3_Finalize(void *priv)
{
    sha3_context *ctx = (sha3_context *) priv;

    ctx->s[12] |= 0x600000000;
    ctx->s[16] = SHA3_CONST(0x8000000000000000UL);

    keccakf(ctx->s);

    *(uint64_t*)&ctx->sb[0] = ctx->s[0];
    *(uint64_t*)&ctx->sb[8] = ctx->s[1];
    //*(uint64_t*)&ctx->sb[16] = ctx->s[2];
    //*(uint64_t*)&ctx->sb[24] = ctx->s[3];

    return (ctx->sb);
}

uint64_t sha3(uint8_t *data)
{
    sha3_context c;
    uint8_t *hash;

    memset(&c.s[13], 0, 96);
    memcpy(c.s, data, 100);
    hash = sha3_Finalize(&c);

    char *ssdata = abin2hex((const unsigned char*)hash, 32);
    printf("hash: %s\n", ssdata);
    free(ssdata);

    return *(uint64_t*)hash;
}



int atomminer_scanhash_sha3(int thr_id, struct work *work, uint64_t *hashes_done)
{
    uint8_t *hash;
    const uint32_t first_nonce = work->data[21];
    sha3_context c;

    uint32_t n = first_nonce;
    uint64_t tt7 = (*((uint64_t*)&work->target[6]));
    //uint32_t t7 = work->target[7];
    //uint32_t t6 = work->target[6];

    do {
        memcpy(&work->data[24], &n, 4);
        memset(&c.s[12], 0, 104);
        memcpy(c.s, work->data, 100);
        hash = sha3_Finalize(&c);
        //uint64_t hash7 = swap64(*((uint64_t*)&hash[0]));
        uint32_t hh7 = swab32(*((uint32_t*)&hash[0]));
        uint32_t hh6 = swab32(*((uint32_t*)&hash[4]));
        uint64_t hash7 = (((uint64_t)hh7)<<32)|hh6;

//        char *ss1 = abin2hex(hash, 32);
//        applog(LOG_DEBUG, "data: %s\n", ss1);
//        free(ss1);

        if (hash7 <= tt7) {
        //if(hh7 <= t7) {
#ifdef _ALGO_DEBUG
            char *ss = abin2hex(hash, 32);
            applog(LOG_DEBUG, "hash: %s\n", ss);
            free(ss);

            FILE *f = fopen("/home/dev/projects/apps/cpuminer-sha3/blocks.txt", "a+");
            ss = abin2hex(&work->data[0], 100);
            applog(LOG_DEBUG, "data: %s\n", ss);
            fprintf(f, "data: %s\n", ss);
            free(ss);
            ss = abin2hex(hash, 32);
            applog(LOG_DEBUG, "hash: %s\n", ss);
            fprintf(f, "hash: %s\n", ss);
            free(ss);
            ss = abin2hex(&work->target[0], 32);
            applog(LOG_DEBUG, "target: %s\n", ss);
            fprintf(f, "target: %s\n", ss);
            free(ss);
            fprintf(f, "----------------------------------\n");
            fclose(f);
#endif
            //work_set_target_ratio(work, hash);
            *hashes_done = n - first_nonce + 1;
            return true;
        }
        n++;

    } while (n < 0xffffffff && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce + 1;
    return 0;
}
