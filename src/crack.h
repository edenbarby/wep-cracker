#ifndef CRACK_H
#define CRACK_H


#include <algorithm>
#include <array>
#include <unordered_map>
#include <vector>


class Crack {

public:

    Crack(int keySize);
    bool add(int output, std::array<int, 3> iv);
    std::vector<int> get_key(void);

private:

    int iv_to_hash(std::array<int, 3> iv);
    bool is_resolved(int output, std::array<int, 3> iv);
    bool attempt_next_word();
    void reset(void);

    int keySize;
    std::array<int, 256> initialState;

    std::vector<int> key;
    std::unordered_map<int, int> outputs;
    std::unordered_map<int, std::array<int, 3>> ivs;

    int voteCount;
    int voteThreshold;
    std::array<int, 256> votes;

};


#endif // CRACK_H