#include "wired_equivalent_privacy.h"


WiredEquivalentPrivacy::WiredEquivalentPrivacy(std::array<int, 3> initializationVector, std::vector<int> key) {
    std::vector<int> rootKey;

    rootKey.insert(rootKey.end(), initializationVector.begin(), initializationVector.end());
    rootKey.insert(rootKey.end(), key.begin(), key.end());

    rc4_ = new RivestCipher4(rootKey);
}

int WiredEquivalentPrivacy::next() {
    return rc4_->next();
}

std::vector<int> WiredEquivalentPrivacy::encrypt(std::vector<int> plaintext) {
    std::vector<int> ciphertext;

    for(int i = 0; i < plaintext.size(); i++) {
        ciphertext.push_back(plaintext.at(i) ^ rc4_->next());
    }

    return ciphertext;
}