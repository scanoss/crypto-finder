#include <stdio.h>
#include <openssl/evp.h>

#if 0
// Line 5: Dead code — the #if 0 branch
void dead_branch() {
    EVP_md5();
}
#else
// Line 10: LIVE code — the #else branch IS compiled
void live_branch() {
    EVP_sha256();
}
#endif

// Line 16: Live code
void normal() {
    EVP_sha1();
}
