#ifndef GENERATOR_H
#define GENERATOR_H


#include "wired_equivalent_privacy.h"
#include <vector>
#include <array>


class Generator {

public:

    Generator();
    void next_iv(std::array<int, 3> &iv);
    int get_output(std::array<int, 3> iv);

private:



    int i_, a_, b_, c_;
    std::vector<int> secretKey_;

};


#endif // GENERATOR_H