#include <stdio.h>
#include <openssl/evp.h>

// Line 4: Live code
void live() {
    EVP_md5();
}

#if 0
// Line 10: Dead — outer #if 0
void dead_outer() {
    EVP_sha256();

    #ifdef USE_AES
    // Line 15: Still dead — nested inside #if 0
    EVP_aes_128_cbc();
    #endif

    #if 1
    // Line 20: Still dead — nested inside outer #if 0
    EVP_sha512();
    #endif
}
#endif

// Line 26: Live code
void live_after() {
    EVP_sha1();
}
