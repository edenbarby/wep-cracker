#include "crack.h"

Crack::Crack(int keySize) {
    this->keySize = keySize;
    for(int i = 0; i < 256; i++) {
        this->initialState.at(i) = i;
    }
    this->reset();
}

bool Crack::add(int output, std::array<int, 3> iv) {
    bool nextWordSuccess;
    int hash;

    hash = iv_to_hash(iv);
    this->outputs.emplace(hash, output);
    this->ivs.emplace(hash, iv);

    nextWordSuccess = false;

    if(this->is_resolved(output, iv) && this->voteCount > this->voteThreshold) {
        while(this->attempt_next_word()) {
            if(this->key.size() == this->keySize) {
                return true;
            }

            for(auto e : ivs) {
                hash = e.first;
                iv = e.second;
                output = outputs.at(hash);

                this->is_resolved(output, iv);
            }
        }
    }

    return false;
}

std::vector<int> Crack::get_key(void) {
    return this->key;
}

void Crack::reset(void) {
    this->voteCount = 0;
    this->voteThreshold = 60;
    std::fill(this->votes.begin(), this->votes.end(), 0);
}

int Crack::iv_to_hash(std::array<int, 3> iv) {
    return 256 * (256 * iv.at(0) + iv.at(1)) + iv.at(2);
}

bool Crack::is_resolved(int output, std::array<int, 3> iv) {
    int i, j, tmp, outputIndex, vote;
    std::array<int, 256> state;
    std::vector<int> knownKey;

    state = std::array<int, 256>(this->initialState);
    knownKey.insert(knownKey.end(), iv.begin(), iv.end());
    knownKey.insert(knownKey.end(), this->key.begin(), this->key.end());

    // for(int i = 0; i < iv.size(); i++) {
    //     printf("%i ", iv.at(i));
    // }

    j = 0;
    for(i = 0; i < knownKey.size(); i++) {
        j = (j + state.at(i) + knownKey.at(i)) % 256;
        tmp = state.at(i);
        state.at(i) = state.at(j);
        state.at(j) = tmp;
    }

    // printf(" %i", state.at(1));
    // printf(" %i", state.at(1) + state.at(state.at(1)));

    if((state.at(1) < knownKey.size()) &&
            ((state.at(1) + state.at(state.at(1))) == knownKey.size())) {

        // printf("!!!!");

        for(outputIndex = 0; outputIndex < state.size(); outputIndex++) {
            if(state.at(outputIndex) == output) break;
        }
        vote = (outputIndex - j - state.at(knownKey.size())) % 256;
        if(vote < 0) vote += 256;

        this->voteCount++;
        this->votes.at(vote) += 1;

    // printf("\n");
        return true;
    }

    // printf("\n");
    return false;
}

bool Crack::attempt_next_word() {
    int count, highestVote, highestVoteIndex, secondHighestVote;

    highestVote = 0;
    secondHighestVote = 0;

    for(int i = 0; i < this->votes.size(); i++) {
        count = this->votes.at(i);
        if(highestVote < count) {
            highestVote = count;
            highestVoteIndex = i;
        } else if(secondHighestVote < count) {
            secondHighestVote = count;
        }

        // printf("%i %i\n", i, count);
    }

    // printf("highest vote %i\n", highestVote);
    // printf("highest vote ratio %f\n", (double)highestVote / this->voteCount);
    // printf("second highest vote %i\n", secondHighestVote);
    // printf("highest vote index %i\n", highestVoteIndex);

    if(((double)highestVote / this->voteCount > 0.035) && (highestVote > 1.5 * secondHighestVote)) {
        this->key.push_back(highestVoteIndex);
        this->reset();
        return true;
    }

    this->voteThreshold += 30;
    return false;
}