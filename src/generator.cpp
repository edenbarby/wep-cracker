#include "generator.h"

Generator::Generator(std::vector<int> secretKey) {
    this->i_ = 0;
    secretKey_ = secretKey;
}

void Generator::next(int &output, std::array<int, 3> &iv) {
    this->next_iv(iv);
    output = this->get_output(iv);
}

void Generator::next_iv(std::array<int, 3> &iv) {
    this->a_ = (int)(this->i_ / (256 * 256));

    if(this->a_ == 0) {
        this->b_ = (int)(this->i_ / 256);

        if(this->b_ == 0) {
            this->c_ = this->i_;
        } else {
            this->c_ = this->i_ - 256 * this->b_;
        }
    } else {
        this->b_ = (int)(this->i_ / 256) - 256 * this->a_;

        if(this->b_ == 0) {
            this->c_ = this->i_ - 256 * 256 * this->a_;
        } else {
            this->c_ = this->i_ - 256 * this->b_ - 256 * 256 * this->a_;
        }
    }

    iv.at(0) = this->a_;
    iv.at(1) = this->b_;
    iv.at(2) = this->c_;

    this->i_++;
    if(this->i_ >= 16777216) this->i_ = 0;
}

int Generator::get_output(std::array<int, 3> iv) {
    WiredEquivalentPrivacy wep(iv, secretKey_);
    return wep.next();
}