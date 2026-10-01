#include <openssl/evp.h>

int main(void) {
    const EVP_MD *md = EVP_md5();
    return md == NULL;
}
