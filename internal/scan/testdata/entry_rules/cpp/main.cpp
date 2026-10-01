#include <openssl/evp.h>

int main(int argc, char **argv) {
    const EVP_MD *md = EVP_sha1();
    return md == nullptr;
}
