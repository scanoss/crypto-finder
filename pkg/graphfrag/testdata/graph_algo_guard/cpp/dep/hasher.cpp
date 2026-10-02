#include "hasher.hpp"
#include <openssl/sha.h>

namespace dep {

std::string Sha256Hasher::sum(const std::string &data) {
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(data.data()), data.size(), md);
    return std::string(reinterpret_cast<char *>(md), sizeof(md));
}

}  // namespace dep
