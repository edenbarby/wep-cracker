cmake_minimum_required(VERSION 2.6)
project(wifi_hack)

add_executable(wifi_hack main.cpp)
target_link_libraries(wifi_hack pcap)