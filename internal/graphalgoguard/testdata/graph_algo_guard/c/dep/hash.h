#ifndef DEP_HASH_H
#define DEP_HASH_H

int dep_sha256(const unsigned char *data, unsigned long len, unsigned char *out, unsigned int *out_len);

#endif
