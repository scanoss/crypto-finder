#include <stdio.h>
#include "hash.h"

static void print_digest(const unsigned char *md, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char md[32];
    unsigned int len = 0;
    if (dep_sha256((const unsigned char *)"abc", 3, md, &len) == 0) {
        print_digest(md, len);
    }
    return 0;
}
