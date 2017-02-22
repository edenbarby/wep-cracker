#include "rivest_cipher_4.h"

RivestCipher4::RivestCipher4(std::vector<int> rootkey)
{
    state_ = new std::vector<int>();

    for(i_ = 0; i_ < 256; i_++) {
        state_->push_back(i_);
    }

    int tmp;
    for(i_ = 0; i_ < 256; i_++) {
        j_ = (j_ + state_->at(i_) + rootkey.at(i_ % rootkey.size())) % 256;

        tmp = state_->at(i_);
        state_->at(i_) = state_->at(j_);
        state_->at(j_) = tmp;
    }

    i_ = 0;
    j_ = 0;
}

int RivestCipher4::next() {
    i_ = (i_ + 1) % 256;
    j_ = (j_ + state_->at(i_)) % 256;

    int tmp = state_->at(i_);
    state_->at(i_) = state_->at(j_);
    state_->at(j_) = tmp;
    
    return state_->at((state_->at(i_) + state_->at(j_)) % 256);
}