#include <stdio.h>
#include <openssl/evp.h>

// Line 4: Live
void live1() { EVP_md5(); }

#if (0)
// Line 7: Dead — parenthesized zero
void dead_parens() { EVP_sha256(); }
#endif

// Line 11: Live
void live2() { EVP_sha1(); }

#if 0x0
// Line 14: Dead — hex zero
void dead_hex() { EVP_aes_128_cbc(); }
#endif

// Line 18: Live
void live3() { EVP_sha512(); }

#if 00
// Line 21: Dead — octal zero
void dead_octal() { EVP_des_cbc(); }
#endif

// Line 25: Live
void live4() { EVP_md5(); }

#if !1
// Line 28: Dead — logical NOT 1
void dead_not() { EVP_rc4(); }
#endif

// Line 32: Live
void live5() { EVP_sha256(); }

#if 0 && FEATURE_ENABLED
// Line 35: Dead — short circuit
void dead_short() { EVP_aes_256_gcm(); }
#endif

// Line 39: Live
void live6() { EVP_sha384(); }
