#ifndef RIVEST_CIPHER_4_H
#define RIVEST_CIPHER_4_H

#include <vector>

class RivestCipher4 {

public:

    RivestCipher4();
    RivestCipher4(std::vector<int> rootkey);
    int next();

private:

    static const int SIZE = 256;

    int i_;
    int j_;
    std::vector<int> *state_;

};

#endif // RIVEST_CIPHER_4_H