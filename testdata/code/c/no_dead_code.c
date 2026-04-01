#include <stdio.h>
#include <openssl/evp.h>

#ifdef USE_MD5
void maybe_md5() {
    EVP_md5();
}
#endif

#if 0x1
// This IS compiled — 0x1 is hex 1, not zero
void hex_one() {
    EVP_sha256();
}
#endif

void always_live() {
    EVP_sha1();
}
