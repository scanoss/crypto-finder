#include <stdio.h>
#include <openssl/evp.h>

// Line 4: Live code — should be detected
void live_function() {
    EVP_md5();
}

#if 0
// Line 10: Dead code — should NOT be detected
void dead_function() {
    EVP_sha256();
}
#endif

// Line 16: Live code — should be detected
void another_live() {
    EVP_sha1();
}

#if 0
// Line 22: Dead code block 2
void also_dead() {
    EVP_aes_128_cbc();
}
#endif
