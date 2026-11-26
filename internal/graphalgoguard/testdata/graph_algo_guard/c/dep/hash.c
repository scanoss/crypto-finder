#include <openssl/evp.h>
#include "hash.h"

static int digest_with(const EVP_MD *md, const unsigned char *data, unsigned long len, unsigned char *out, unsigned int *out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }
    int ok = EVP_DigestInit_ex(ctx, md, NULL) && EVP_DigestUpdate(ctx, data, len) && EVP_DigestFinal_ex(ctx, out, out_len);
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

int dep_sha256(const unsigned char *data, unsigned long len, unsigned char *out, unsigned int *out_len) {
    return digest_with(EVP_sha256(), data, len, out, out_len);
}
