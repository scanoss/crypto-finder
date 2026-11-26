#include <acme/seal.h>

void other_param(const char *alg);

void from_other_file(void)
{
    other_param("ACME-AES-192");
}
