#include <acme/seal.h>

static void seal_with(const char *alg, int n)
{
    acme_seal(alg, n);
}

static void middle(const char *name)
{
    seal_with(name, 1);
}

static void top(void)
{
    middle("ACME-AES-256");
}

static void direct(void)
{
    const char *a = "ACME-AES-128";
    acme_seal(a, 2);
}

void other_param(const char *alg)
{
    acme_seal(alg, 3);
}

static void untainted(void)
{
    seal_with("ACME-DES", 4);
}

static void deep4(const char *x) { acme_seal(x, 5); }
static void deep3(const char *x) { deep4(x); }
static void deep2(const char *x) { deep3(x); }
static void deep1(const char *x) { deep2(x); }
static void deep0(void) { deep1("ACME-AES-512"); }
