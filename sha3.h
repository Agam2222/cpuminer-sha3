#ifndef SHA3_H
#define SHA3_H

typedef struct sha3_context_ {
    uint64_t saved;
    union {                     /* Keccak's state */
        uint64_t s[25];
        uint8_t sb[25 * 8];
    };
} sha3_context;


/* For Init or Reset call these: */
void sha3_Init256(void *priv);

void sha3_Update(void *priv, void const *bufIn, size_t len);

void const *sha3_Finalize(void *priv);

#endif
