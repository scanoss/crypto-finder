#pragma once
#include <string>

namespace dep {

class Hasher {
public:
    virtual ~Hasher() = default;
    virtual std::string sum(const std::string &data) = 0;
};

class Sha256Hasher : public Hasher {
public:
    std::string sum(const std::string &data) override;
};

}  // namespace dep
