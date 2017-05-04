BasicServiceSet::BasicServiceSet() {
}

void BasicServiceSet::set_ssid(std:string ssid) {
    this->ssid = ssid;
}

void BasicServiceSet::set_bssid(MACAddress bssid) {
    this->bssid = bssid;
}

void BasicServiceSet::set_access_point(MACAddress access_point) {
    this.access_point_address = access_point;
}

void BasicServiceSet::add_station(MACAddress station) {
    this.station_address.insert(station);
}