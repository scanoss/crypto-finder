#include <iostream>
#include <memory>
#include "hasher.hpp"

namespace app {

class LoggingHasher : public dep::Hasher {
public:
    std::string sum(const std::string &data) override {
        std::cout << "hashing" << std::endl;
        return inner_.sum(data);
    }

private:
    dep::Sha256Hasher inner_;
};

std::string fingerprint(dep::Hasher &hasher, const std::string &text) {
    return hasher.sum(text);
}

}  // namespace app

int main() {
    app::LoggingHasher logging;
    std::unique_ptr<dep::Hasher> plain = std::make_unique<dep::Sha256Hasher>();
    std::cout << app::fingerprint(logging, "a") << app::fingerprint(*plain, "b") << std::endl;
    return 0;
}
