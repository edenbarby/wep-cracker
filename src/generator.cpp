#include "generator.h"

Generator::Generator() {
    i_ = 0;
    secretKey_ = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
}

void Generator::next_iv(std::array<int, 3> &iv) {
    a_ = (int)(i_ / (256 * 256));

    if(a_ == 0) {
        b_ = (int)(i_ / 256);

        if(b_ == 0) {
            c_ = i_;
        } else {
            c_ = i_ - 256 * b_;
        }
    } else {
        b_ = (int)(i_ / 256) - 256 * a_;

        if(b_ == 0) {
            c_ = i_ - 256 * 256 * a_;
        } else {
            c_ = i_ - 256 * b_ - 256 * 256 * a_;
        }
    }

    iv.at(0) = a_;
    iv.at(1) = b_;
    iv.at(2) = c_;

    i_++;
    if(i_ >= 16777216) i_ = 0;
}

int Generator::get_output(std::array<int, 3> iv) {
    WiredEquivalentPrivacy wep(iv, secretKey_);
    return wep.next();
}