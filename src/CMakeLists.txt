cmake_minimum_required(VERSION 3.1.0 FATAL_ERROR)

project(wifi_hack)

set(MAIN main.cpp)
set(SOURCES crack.cpp generator.cpp radiotap.cpp rivest_cipher_4.cpp wired_equivalent_privacy.cpp)
set(HEADERS crack.h generator.h radiotap.h rivest_cipher_4.h wired_equivalent_privacy.h)

add_executable(wifi_hack ${MAIN} ${SOURCES} ${HEADERS})
target_link_libraries(wifi_hack pcap)
target_compile_features(wifi_hack PRIVATE cxx_range_for)