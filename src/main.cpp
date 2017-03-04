#include <pcap.h>

// #include <arpa/inet.h>
// #include <netinet/if_ether.h>
// #include <netinet/in.h>
// #include <sys/socket.h>
#include <endian.h>

// #include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "radiotap/radiotap.h"

void parse(const u_char *packet);
char * byte_to_string(uint8_t byte);



int main(int argc, char** argv) {
    int errno;
    char *device_name;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *device_handle;
    const u_char *packet;
    struct pcap_pkthdr pcap_header;
    struct ether_header *ethernet_header;

    // device_name = pcap_lookupdev(error_buffer);
    // if(device_name == NULL) {
    //     printf("%s\n", error_buffer);
    //     return 1;
    // }
    // printf("Using device: %s\n", device_name);

    device_handle = pcap_create(argv[1], error_buffer);
    if(device_handle == NULL) {
        printf("%s\n", error_buffer);
        return 1;
    }
    printf("Device handle created.\n");

    errno = pcap_can_set_rfmon(device_handle);
    if(errno == 1) {
        pcap_set_rfmon(device_handle, 1);
    } else if(errno == 0) {
        printf("Device does not support monitor mode.\n");
        return 1;
    } else if(errno < 0) {
        printf("Error %i: ", errno);
        switch(errno) {
            case PCAP_ERROR_NO_SUCH_DEVICE:
            printf("No such device.");
            break;

            case PCAP_ERROR_PERM_DENIED:
            printf("Permission denied.");
            break;

            case PCAP_ERROR_ACTIVATED:
            printf("Capture handle has already been activated.");
            break;

            case PCAP_ERROR:
            printf("%s", pcap_geterr(device_handle));
            break;

            default:
            printf("%s", pcap_statustostr(errno));
            break;
        }
        printf("\n");
        return 1;
    }
    printf("Monitor mode set.\n");

    // errno = pcap_set_snaplen(device_handle, 1);
    // if(errno != 0) {
    //     printf("%s\n", pcap_statustostr(errno));
    //     return 1;
    // }

    errno = pcap_set_timeout(device_handle, 5000);
    if(errno != 0) {
        printf("%s\n", pcap_statustostr(errno));
        return 1;
    }

    // errno = pcap_set_buffer_size(device_handle, (2*1024*1024));
    // if(errno != 0) {
    //     printf("%s\n", pcap_statustostr(errno));
    //     return 1;
    // }

    errno = pcap_activate(device_handle);
    if(errno < 0) {
        printf("Error %i: ", errno);
        switch(errno) {
            case PCAP_ERROR:
            printf("%s", pcap_geterr(device_handle));
            break;

            default:
            printf("%s", pcap_statustostr(errno));
            break;
        }
        printf("\n");
        return 1;
    }
    printf("Network device activated successfully.\n");
    if(errno > 0) {
        printf("Warning %i:", errno);
        switch(errno) {
            case PCAP_WARNING:
            printf("%s", pcap_geterr(device_handle));
            break;

            default:
            printf("%s", pcap_statustostr(errno));
            break;
        }
        printf("\n");
    }

    packet = pcap_next(device_handle, &pcap_header);
    if(packet == NULL) {
        printf("No packet grabbed!\n");
        return 1;
    }

    printf("Packet grabbed!\n");
    printf("Packet length: %d\n", pcap_header.len);
    printf("Received at: %s", ctime((const time_t*)&pcap_header.ts.tv_sec));
    printf("Packet:\n");
    printf("Byte  Hex   Bin\n");
    for(int i = 0; i < pcap_header.len; i++) {
        printf("%4i  0x%02x  %s\n", i, packet[i], byte_to_string(packet[i]));
    }

    parse(packet);
}


void parse(const u_char *packet) {
    int present;
    uint8_t version, pad;
    uint16_t length;
    uint32_t flags;

    version = (uint8_t)(packet[0]);
    pad = (uint8_t)(packet[1]);
    length = le16toh((uint16_t)(packet[2]));
    flags = le32toh((uint32_t)(packet[4]));

    printf("Radiotap header length: %i\n", length);

    printf("Radiotap flags:\n");

    for(int i = 0; i < 32; i++) {
        present = 1;
        switch((ieee80211_radiotap_type)(i)) {
            case IEEE80211_RADIOTAP_TSFT:
                printf("TSFT");
                break;
            case IEEE80211_RADIOTAP_FLAGS:
                printf("Flags");
                break;
            case IEEE80211_RADIOTAP_RATE:
                printf("Rate");
                break;
            case IEEE80211_RADIOTAP_CHANNEL:
                printf("Channel");
                break;
            case IEEE80211_RADIOTAP_FHSS:
                printf("FHSS");
                break;
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                printf("dBm Antenna Signal");
                break;
            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                printf("dBm Antenna Noise");
                break;
            case IEEE80211_RADIOTAP_LOCK_QUALITY:
                printf("Lock Quality");
                break;
            case IEEE80211_RADIOTAP_TX_ATTENUATION:
                printf("Tx Attenuation");
                break;
            case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
                printf("dB Tx Attenuation");
                break;
            case IEEE80211_RADIOTAP_DBM_TX_POWER:
                printf("dBm Tx Power");
                break;
            case IEEE80211_RADIOTAP_ANTENNA:
                printf("Antenna");
                break;
            case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
                printf("dB Antenna Signal");
                break;
            case IEEE80211_RADIOTAP_DB_ANTNOISE:
                printf("dB Antenna Noise");
                break;
            case IEEE80211_RADIOTAP_RX_FLAGS:
                printf("Rx Flags");
                break;
            case IEEE80211_RADIOTAP_TX_FLAGS:
                printf("Tx Flags");
                break;
            case IEEE80211_RADIOTAP_RTS_RETRIES:
                printf("RTS Retries");
                break;
            case IEEE80211_RADIOTAP_DATA_RETRIES:
                printf("Data Retries");
                break;
            case IEEE80211_RADIOTAP_MCS:
                printf("MCS Information");
                break;
            case IEEE80211_RADIOTAP_AMPDU_STATUS:
                printf("A-MPDU Status");
                break;
            case IEEE80211_RADIOTAP_VHT:
                printf("VHT Information");
                break;
            case IEEE80211_RADIOTAP_TIMESTAMP:
                printf("Timestamp");
                break;
            case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
                printf("Radiotap Namespace");
                break;
            case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
                printf("Vender Namespace");
                break;
            case IEEE80211_RADIOTAP_EXT:
                printf("Ext");
                break;
            default:
                present = 0;
                break;
        }

        if(present) {
            printf(": ");
            if((flags >> i) & 0x1) {
                printf("present");
            } else {
                printf("absent");
            }
            printf("\n");
        }
    }
}


char * byte_to_string(uint8_t byte) {
    int i;
    static char string[9];

    for(i = 0; i < 8; i++) {
        if(i > 3) {
            if(i == 4) string[i] = ' ';
            string[i+1] = ((byte >> (7 - i)) & 0x1) + '0';
        } else {
            string[i] = ((byte >> (7 - i)) & 0x1) + '0';
        }
    }

    return string;
}



































// #include <iostream>
// #include <string>
// #include <vector>

// #include "generator.h"
// #include "crack.h"


// std::string password = "Hello World!";


// int main(int argc, char **argv) {
//     std::vector<int> secretKey(password.begin(), password.end());
//     Generator gen(secretKey);
//     Crack cracker(secretKey.size());

//     int output;
//     std::array<int, 3> iv;
//     std::vector<int> knownKey;

//     std::cout << "Cracking password..." << std::endl;
//     int count = 0;
//     while(true) {
//         gen.next(output, iv);
//         if(cracker.add(output, iv)) {
//             knownKey = cracker.get_key();
//             break;
//         }

//         if(++count % 10000 == 0) {
//             std::cout << count << " ivs tested. The key so far";
//             knownKey = cracker.get_key();
//             for(int i = 0; i < knownKey.size(); i++) {
//                 printf(" %c", knownKey.at(i));
//             }
//             std::cout << "." << std::endl;
//         }
//     }

//     std::cout << "Cracked after " << count << " ivs!" << std::endl;

//     for(int i = 0; i < knownKey.size(); i++) {
//         printf(" %c", knownKey.at(i));
//     }
//     printf("\n");
// }

// std::vector<int> iv = {0, 0, 254};

// std::vector<int> stateInitial;

// std::unordered_map<int, bool> isResolved;
// std::unordered_map<int, std::vector<int>> resolvedIVs;

// int targetJ;
// std::vector<int> targetState;

// Generator gen;



// int hash_iv(std::array<int, 3> iv) {
//     return iv.at(2) + 256 * ( iv.at(1) + 256 * iv.at(0) );
// }

// bool is_resolved(std::array<int, 3> iv, std::vector<int> knownKey, int &j, std::array<int, 256> &state) {
//     int i, tmp;
//     std::vector<int> key;

//     key.insert(key.end(), iv.begin(), iv.end());
//     key.insert(key.end(), knownKey.begin(), knownKey.end());

//     if(key.size() < 3 || key.size() > 50) {
//         std::cout << "is_resolved: unusual key size (" << key.size() << ")." << std::endl;
//     }

//     j = 0;
//     for(i = 0; i < key.size(); i++) {
//         j = (j + state.at(i) + key.at(i)) % 256;
//         tmp = state.at(i);
//         state.at(i) = state.at(j);
//         state.at(j) = tmp;
//     }

//     if(state.at(1) < key.size() &&
//             (state.at(1) + state.at(state.at(1))) == key.size()) {
//         return true;
//     }
//     return false;
// }

// std::vector<int> crack(int keySize, std::unordered_map<int, int> outputs, std::unordered_map<int, std::vector<int>> ivs) {
//     int output, ivHash, j;
//     std::array<int, 3> iv;
//     std::array<int, 256> state, stateInitial, votes;
//     std::vector<int> key;

//     for(int i = 0; i < 256; i++) {
//         stateInitial.at(i) = i;
//         votes.at(i) = 0;
//     }

//     for(auto element : ivs) {
//         ivHash = element.first;
//         iv = element.second;
//         state = std::array<int, 256>(stateInitial);
//         if(is_resolved(iv, key, j, state)) {

//         }

//         output = outputs.at(ivHash);
//     }
// }





// int get_next_secret(std::vector<int> known) {
//     int j;
//     std::array<int, 3> iv;
//     std::array<int, 256> state, stateInitial, votes;
//     std::vector<int> knownKey;
//     Generator gen;

//     std::fill(votes.begin(), votes.end(), 0);

//     for(int i = 0; i < 256; i++) {
//         stateInitial.at(i) = i;
//     }

//     while(1) {
//         printf("Resolved IVs found: ");
//         while(resolvedCount < resolvedTarget) {
//             // knownKey = gen.next_iv();
//             gen.next_iv(iv);
//             knownKey = std::vector<int>();
//             knownKey.insert(knownKey.end(), iv.begin(), iv.end());
//             knownKey.insert(knownKey.end(), key.begin(), key.end());

//             // for(auto i : iv) {
//             //     std::cout << i << " ";
//             // }
//             // std::cout << std::endl;

//             state = std::array<int, 256>(stateInitial);
//             if(is_resolved(knownKey, j, state)) {
//                 resolvedCount++;

//                 int output = gen.get_output(iv);
//                 int outputIndex;
//                 for(outputIndex = 0; outputIndex < state.size(); outputIndex++) {
//                     if(state.at(outputIndex) == output) break;
//                 }
//                 if(outputIndex == state.size()) {
//                     std::cout << "get_next_key_word: could not find output in state (" << output << ")." << std::endl;
//                 }

//                 int vote = (outputIndex - j - state.at(knownKey.size())) % 256;
//                 if(vote < 0) vote += 256;
//                 votes.at(vote) += 1;

//                 if(resolvedCount % 10 == 0) {
//                     std::cout << resolvedCount << " " << std::flush;
//                 }
//             }
//         }

//         int count, highestVote, highestVoteIndex, secondHighestVote;
//         double averageVote;

//         printf("\nSufficient resolved IVs found, attempting to determine the key word.\n");

//         highestVote = 0;
//         secondHighestVote = 0;
//         averageVote = 0;
//         for(int i = 0; i < votes.size(); i++) {
//             count = votes.at(i);
//             if(highestVote < count) {
//                 highestVote = count;
//                 highestVoteIndex = i;
//             } else if(secondHighestVote < count) {
//                 secondHighestVote = count;
//             }
//             averageVote += count;
//         }
//         averageVote /= 256;

//         // for(int i = 0; i < votes.size(); i++) {
//         //     printf("%i: %i\n", i, votes.at(i));
//         // }
//         // printf("Highest vote: %i (%i)\n", highestVote, highestVoteIndex);
//         // printf("Second highest vote: %i\n", secondHighestVote);
//         // printf("Average vote: %f\n", averageVote);

//         if(highestVote > 8 * averageVote && highestVote > 1.5 * secondHighestVote) {
//             return highestVoteIndex;
//         }

//         resolvedTarget += 200;
//     }
// }




    // int keyWord;
    // std::vector<int> key;

    // for(int i = 0; i < 11; i++) {
    //     printf("Searching...\n");
    //     keyWord = get_next_key_word(key);
    //     key.push_back(keyWord);
    //     printf("The %ith key word found: %i\n", i+1, keyWord);
    // }

    // printf("Done! The key is [ ");
    // for(auto i : key) {
    //     printf("%c ", i);
    // }
    // printf("].\n");




    // std::string str;
    // std::stringstream ss;
    // std::array<int, 3> iv;
    // std::vector<int> knownKey;
    // std::vector<std::array<int, 3>> ivs;
    // Generator gen;

    // for(int i = 0; i < 256; i++) {
    //     stateInitial.push_back(i);
    // }

    // for(int i = 0; i < 256*256*256; i++) {
    //     ss = std::stringstream();
    //     gen.next_iv(iv);
    //     knownKey = std::vector<int>(iv.begin(), iv.end());

    //     if(resolved_check(knownKey)) {
    //         ss << " 1";
    //     }
    //     if(resolved_check2(knownKey)) {
    //         ss << " 2";
    //     }
    //     if(resolved_check3(knownKey)) {
    //         ss << " 3";
    //     }

    //     if(ss.str().size() > 0) {
    //         for(auto i : knownKey) {
    //             std::cout << i << " ";
    //         }
    //         std::cout << ss.str() << std::endl;
    //     }
    //     // for(auto i : knownKey) {
    //     //     std::cout << i << " ";
    //     // }
    //     // std::cout << ss.str() << std::endl;
    // }











    // int a, b, c;
    // int radix = 256;
    // int i = 0;
    // std::vector<int> iv1 = {0, 0 ,0};
    // std::vector<int> iv2 = {0, 0 ,0};
    // Generator gen2;

    // auto t1 = std::chrono::high_resolution_clock::now();
    // for(int i = 0; i < 1000000; i++) {
    //     iv1.at(0) = (int)(i / (256 * 256));

    //     iv1.at(1) = (int)(i / (256)) - 256 * iv1.at(0);

    //     iv1.at(2) = i - 256 * iv1.at(1) - 256 * 256 * iv1.at(0);

    //     // for(auto i : iv1) {
    //     //     std::cout << i << " ";
    //     // }
    //     // std::cout << std::endl;
    // }
    // auto t2 = std::chrono::high_resolution_clock::now();

    // auto t3 = std::chrono::high_resolution_clock::now();
    // for(int i = 0; i < 1000000; i++) {
    //     a = (int)(i / (256 * 256));
    //     if(a == 0) {
    //         b = (int)(i / 256);
    //         if(b == 0) {
    //             c = i;
    //         } else {
    //             c = i - 256 * b;
    //         }
    //     } else {
    //         b = (int)(i / 256) - 256 * a;
    //         if(b == 0) {
    //             c = i - 256 * 256 * c;
    //         } else {
    //             c = i - 256 * b - 256 * 256 * c;
    //         }
    //     }

    //     iv2.at(0) = a;
    //     iv2.at(1) = b;
    //     iv2.at(2) = c;

    //     // for(auto i : iv2) {
    //     //     std::cout << i << " ";
    //     // }
    //     // std::cout << std::endl;

    //     // i++;
    // }
    // auto t4 = std::chrono::high_resolution_clock::now();

    // std::cout << "Method 1: " 
    //           << std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count()
    //           << " ms" << std::endl;

    // std::cout << "Method 2: " 
    //           << std::chrono::duration_cast<std::chrono::milliseconds>(t4 - t3).count()
    //           << " ms" << std::endl;





















    // bool resolved;
    // std::vector<int> iv;
    // Generator gen = Generator();

    // for(int i = 0; i < 256; i++) {
    //     stateInitial.push_back(i);
    // }

    // for(int i = 0; i < 5 * (256*256*256); i++) {
    //     iv = gen.next_iv();
    //     resolved = false;

    //     if(i > 1 * (256*256*256)) {
    //         auto search = isResolved.find(hash_iv(iv));
    //         if(search == isResolved.end()) {
    //             if(resolved_check(iv)) {
    //                 isResolved.emplace(hash_iv(iv), true);
    //                 resolvedIVs.emplace(hash_iv(iv), iv);
    //                 resolved = true;
    //             } else {
    //                 isResolved.emplace(hash_iv(iv), false);
    //             }
    //         } else {
    //             if(search->second) {
    //                 resolved = true;
    //             }
    //         }
    //     } else {
    //         if(resolved_check(iv)) {
    //             isResolved.emplace(hash_iv(iv), true);
    //             resolvedIVs.emplace(hash_iv(iv), iv);
    //             resolved = true;
    //         } else {
    //             isResolved.emplace(hash_iv(iv), false);
    //         }
    //     }

    //     if(resolved) {
    //         for(auto i : iv) {
    //             std::cout << i << " ";
    //         }
    //         std::cout << std::endl;
    //     }
    // }


    // isResolved.emplace(1, true);
    // isResolved.emplace(10, true);
    // isResolved.emplace(100, true);
    // isResolved.emplace(1000, true);

    // auto search = isResolved.find(100);
    // if(search != isResolved.end()) {
    //     std::cout << "Found " << search->first << " " << search->second << '\n';
    // }
    // else {
    //     std::cout << "Not found\n";
    // }


    // if(isResolved.at(2)) std::cout << isResolved.at(2) << std::endl;


    

    // // WiredEquivalentPrivacy(iv, key);
    // std::vector<int> iv = {0, 0, 0};

    // for(int i = 0; i < 256; i++) {
    //     stateInitial.push_back(i);
    // }

    // for(int i = 0; i < (256*256*256); i++) {
    //     if(resolved_check(iv)) {
    //         for(auto i : iv) {
    //             std::cout << i << " ";
    //         }
    //         std::cout << std::endl;
    //     }

    //     next(iv);
    // }








// /* includes *******************************************************************/

// #include <pcap.h>

// #include <stdio.h>
// #include <stdlib.h>

// /* private typedefs ***********************************************************/
// /* private defines ************************************************************/
// /* private macros *************************************************************/
// /* private variables **********************************************************/
// /* private function prototypes ************************************************/

// static int init(char *interface, pcap_t **pcap_handle);
// static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);


// int main(int argc, char** argv) {
//     int error_code;
//     pcap_t *pcap_handle;

//     if(argc != 2) {
//         fprintf(stderr, "Usage: %s [Network Interface]\n", argv[0]);
//         exit(EXIT_FAILURE);
//     }

//     error_code = init(argv[1], &pcap_handle);
//     if(error_code != 0) {
//         fprintf(stderr, "Initialization failed.\n");
//         exit(EXIT_FAILURE);
//     }

//     pcap_loop(pcap_handle, 0, pcap_callback, "eden");
// }

// /*
// ** @brief
// ** @param
// ** @retval
// */
// static int init(char *interface, pcap_t **pcap_handle) {
//     int error_code;
//     char error_buffer[PCAP_ERRBUF_SIZE];

//     (*pcap_handle) = pcap_create(interface, error_buffer);
//     if((*pcap_handle) == NULL) {
//         fprintf(stderr, "%s\n", error_buffer);
//         return 1;
//     }

//     printf("Attempting enable monitor mode...");
//     error_code = pcap_can_set_rfmon((*pcap_handle));
//     if(error_code == 1) {
//         pcap_set_rfmon((*pcap_handle), 1);
//     } else if(error_code == 0) {
//         fprintf(stderr, "%s does not support monitor mode.\n", interface);
//         return 1;
//     } else if(error_code < 0) {
//         switch(error_code) {
//         case PCAP_ERROR_NO_SUCH_DEVICE:
//             fprintf(stderr, "No such device.");
//             break;

//         case PCAP_ERROR_PERM_DENIED:
//             fprintf(stderr, "Permission denied.");
//             break;

//         case PCAP_ERROR_ACTIVATED:
//             fprintf(stderr, "Capture handle has already been activated.");
//             break;

//         case PCAP_ERROR:
//             fprintf(stderr, "%s", pcap_geterr((*pcap_handle)));
//             break;

//         default:
//             fprintf(stderr, "%s", pcap_statustostr(error_code));
//             break;
//         }
//         fprintf(stderr, "\n");
//         return 1;
//     }
//     printf("Success.\n");

//     error_code = pcap_set_snaplen((*pcap_handle), 65535);
//     if(error_code != 0) {
//         fprintf(stderr, "%s\n", pcap_statustostr(error_code));
//         return 1;
//     }

//     error_code = pcap_set_timeout((*pcap_handle), 5000);
//     if(error_code != 0) {
//         fprintf(stderr, "%s\n", pcap_statustostr(error_code));
//         return 1;
//     }

//     printf("Attempting to activate interface...");
//     error_code = pcap_activate((*pcap_handle));
//     if(error_code < 0) {
//         switch(error_code) {
//         case PCAP_ERROR:
//             fprintf(stderr, "%s", pcap_geterr((*pcap_handle)));
//             break;

//         default:
//             fprintf(stderr, "%s\n", pcap_statustostr(error_code));
//             break;
//         }
//         printf("\n");
//         return 1;
//     }
//     printf("Success.\n");
//     if(error_code > 0) {
//         printf("Warning %i:", error_code);

//         switch(error_code) {
//         case PCAP_WARNING:
//             fprintf(stderr, "%s", pcap_geterr((*pcap_handle)));
//             break;

//         default:
//             fprintf(stderr, "%s\n", pcap_statustostr(error_code));
//             break;
//         }

//         printf("\n");
//     }
// }

// /*
// ** @brief
// ** @param
// ** @retval
// */
// static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
//     uint8_t *frame = (uint8_t *)bytes;
//     struct ieee80211_radiotap_header *radiotap_header;

//     // Check that first 8 bytes is a valid radio tap header.
//     // radiotap_header.it_version = frame[0];
//     // radiotap_header.it_pad     = frame[1];
//     // radiotap_header.it_len     = le16toh((uint16_t)frame[2]);
//     // radiotap_header.it_present = le32toh((uint32_t)frame[4]);

//     radiotap_header = (struct ieee80211_radiotap_header *)bytes;

//     if((radiotap_header.it_version != 0) || (radiotap_header.it_pad != 0)
//         || (radiotap_header.it_len < 8)) {
//         return;
//     }

    
// }










