#ifndef WIRED_EQUIVALENT_PRIVACY_H
#define WIRED_EQUIVALENT_PRIVACY_H

#include <array>
#include <vector>

#include "rivest_cipher_4.h"

class WiredEquivalentPrivacy {

public:

    WiredEquivalentPrivacy(std::array<int, 3> initializationVector, std::vector<int> key);
    int next();
    std::vector<int> encrypt(std::vector<int> plaintext);

private:

    RivestCipher4 *rc4_;

};

#endif // WIRED_EQUIVALENT_PRIVACY_H