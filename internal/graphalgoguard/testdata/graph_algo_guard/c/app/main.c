#include <stdio.h>
#include "hash.h"

static void print_digest(const unsigned char *md, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");
}

struct cfg { int mode; };

static void configure(struct cfg *c, int wide) {
    c->mode = 1;
    if (wide)
        c->mode = 2;
#ifndef NO_NARROW
    else if (c->mode == 1)
        c->mode = 3;
#endif
    else
        c->mode = 4;
    printf("mode %d\n", c->mode);
}

int main(void) {
    unsigned char md[32];
    unsigned int len = 0;
    if (dep_sha256((const unsigned char *)"abc", 3, md, &len) == 0) {
        print_digest(md, len);
    }
    return 0;
}
