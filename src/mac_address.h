#ifndef MAC_ADDRESS_H
#define MAC_ADDRESS_H


#include <array>
#include <iostream>
#include <string>


class MACAddress {

private:

    std::array<uint8_t, 6> address;

public:

    MACAddress(uint8_t *address);
    MACAddress(std::string address);

    bool operator==(const MACAddress& rhs) const;
    bool operator<(const MACAddress& rhs) const;

    friend std::ostream& operator<<(std::ostream&, const MACAddress&);

};


#endif // MAC_ADDRESS_H