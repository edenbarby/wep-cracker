#include "mac_address.h"

MACAddress::MACAddress(uint8_t *address) {
    for(int i = 0; i < 6; i++) {
        this->address.at(i) = address[i];
    }
}

MACAddress::MACAddress(std::string address) {
    if(address.size() != 17) {
        std::cout << "Invalid address size: " << address << std::endl;
        for(int i = 0; i < 6; i++) {
            this->address.at(i) = 0;
        }
        return;
    }

    for(int i = 0; i < 5; i++) {
        if(address.at(3 * i + 2) != ':') {
            std::cout << "Invalid address formatting: " << address << std::endl;
            for(int i = 0; i < 6; i++) {
                this->address.at(i) = 0;
            }
            return;
        }
    }

    for(int i = 0; i < 6; i++) {
        this->address.at(i) = std::stoul(address.substr(3*i, 2), 0, 16);
    }
}

bool MACAddress::operator==(const MACAddress& rhs) const {
    for(int i = 0; i < 6; i++) {
        if(this->address.at(i) != rhs.address.at(i)) return false;
    }
    return true;
}

bool MACAddress::operator<(const MACAddress& rhs) const {
    for(int i = 0; i < 6; i++) {
        if(this->address.at(i) < rhs.address.at(i)) return true;
        if(this->address.at(i) > rhs.address.at(i)) return false;
    }
    return false;
}

std::ostream& operator<<(std::ostream& s, const MACAddress& e) {
    char buffer[4];

    snprintf(buffer, 4, "%02X", e.address.at(0));
    s << std::string(buffer);

    for(int i = 1; i < 6; i++) {
        snprintf(buffer, 4, ":%02X", e.address.at(i));
        s << std::string(buffer);
    }

    return s;
}