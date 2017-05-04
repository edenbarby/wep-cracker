#ifndef BASIC_SERVICE_SET_H
#define BASIC_SERVICE_SET_H

class BasicServiceSet {
    
private:

    std::string ssid;
    MACAddress bssid;
    MACAddress access_point_address;
    set<MACAddress> station_addresses;

public:

    BasicServiceSet();
    void set_ssid(std:string ssid);
    void set_bssid(MACAddress bssid);
    void set_access_point(MACAddress access_point);
    void add_station(MACAddress station);

};

#endif // BASIC_SERVICE_SET_H