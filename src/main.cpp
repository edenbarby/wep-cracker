/*
********************************************************************************
** @file   repo/wep-cracker/src/main.cpp
** @author eden barby
** @date   22nd december 2016
** @brief  
********************************************************************************
** external functions
********************************************************************************
** 
********************************************************************************
*/


/* includes *******************************************************************/

#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>

/* private typedefs ***********************************************************/
/* private defines ************************************************************/
/* private macros *************************************************************/
/* private variables **********************************************************/
/* private function prototypes ************************************************/

static int init(char *interface, pcap_t **pcap_handle);
static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);


int main(int argc, char** argv) {
    int error_code;
    pcap_t *pcap_handle;

    if(argc != 2) {
        fprintf(stderr, "Usage: %s [Network Interface]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    error_code = init(argv[1], &pcap_handle);
    if(error_code != 0) {
        fprintf(stderr, "Initialization failed.\n");
        exit(EXIT_FAILURE);
    }

    pcap_loop(pcap_handle, 0, pcap_callback, "eden");
}

/*
** @brief
** @param
** @retval
*/
static int init(char *interface, pcap_t **pcap_handle) {
    int error_code;
    char error_buffer[PCAP_ERRBUF_SIZE];

    (*pcap_handle) = pcap_create(interface, error_buffer);
    if((*pcap_handle) == NULL) {
        fprintf(stderr, "%s\n", error_buffer);
        return 1;
    }

    printf("Attempting enable monitor mode...");
    error_code = pcap_can_set_rfmon((*pcap_handle));
    if(error_code == 1) {
        pcap_set_rfmon((*pcap_handle), 1);
    } else if(error_code == 0) {
        fprintf(stderr, "%s does not support monitor mode.\n", interface);
        return 1;
    } else if(error_code < 0) {
        switch(error_code) {
        case PCAP_ERROR_NO_SUCH_DEVICE:
            fprintf(stderr, "No such device.");
            break;

        case PCAP_ERROR_PERM_DENIED:
            fprintf(stderr, "Permission denied.");
            break;

        case PCAP_ERROR_ACTIVATED:
            fprintf(stderr, "Capture handle has already been activated.");
            break;

        case PCAP_ERROR:
            fprintf(stderr, "%s", pcap_geterr((*pcap_handle)));
            break;

        default:
            fprintf(stderr, "%s", pcap_statustostr(error_code));
            break;
        }
        fprintf(stderr, "\n");
        return 1;
    }
    printf("Success.\n");

    error_code = pcap_set_snaplen((*pcap_handle), 65535);
    if(error_code != 0) {
        fprintf(stderr, "%s\n", pcap_statustostr(error_code));
        return 1;
    }

    error_code = pcap_set_timeout((*pcap_handle), 5000);
    if(error_code != 0) {
        fprintf(stderr, "%s\n", pcap_statustostr(error_code));
        return 1;
    }

    printf("Attempting to activate interface...");
    error_code = pcap_activate((*pcap_handle));
    if(error_code < 0) {
        switch(error_code) {
        case PCAP_ERROR:
            fprintf(stderr, "%s", pcap_geterr((*pcap_handle)));
            break;

        default:
            fprintf(stderr, "%s\n", pcap_statustostr(error_code));
            break;
        }
        printf("\n");
        return 1;
    }
    printf("Success.\n");
    if(error_code > 0) {
        printf("Warning %i:", error_code);

        switch(error_code) {
        case PCAP_WARNING:
            fprintf(stderr, "%s", pcap_geterr((*pcap_handle)));
            break;

        default:
            fprintf(stderr, "%s\n", pcap_statustostr(error_code));
            break;
        }

        printf("\n");
    }
}

/*
** @brief
** @param
** @retval
*/
static void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    uint8_t *frame = (uint8_t *)bytes;
    struct ieee80211_radiotap_header *radiotap_header;

    // Check that first 8 bytes is a valid radio tap header.
    // radiotap_header.it_version = frame[0];
    // radiotap_header.it_pad     = frame[1];
    // radiotap_header.it_len     = le16toh((uint16_t)frame[2]);
    // radiotap_header.it_present = le32toh((uint32_t)frame[4]);

    radiotap_header = (struct ieee80211_radiotap_header *)bytes;

    if((radiotap_header.it_version != 0) || (radiotap_header.it_pad != 0)
        || (radiotap_header.it_len < 8)) {
        return;
    }

    
}










// #include <pcap.h>

// // #include <arpa/inet.h>
// // #include <netinet/if_ether.h>
// // #include <netinet/in.h>
// // #include <sys/socket.h>
// #include <endian.h>

// // #include <errno.h>
// #include <stdint.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <time.h>

// #include "radiotap/radiotap.h"

// void parse(const u_char *packet);
// char * byte_to_string(uint8_t byte);



// int main(int argc, char** argv) {
//     int errno;
//     char *device_name;
//     char error_buffer[PCAP_ERRBUF_SIZE];
//     pcap_t *device_handle;
//     const u_char *packet;
//     struct pcap_pkthdr pcap_header;
//     struct ether_header *ethernet_header;

//     // device_name = pcap_lookupdev(error_buffer);
//     // if(device_name == NULL) {
//     //     printf("%s\n", error_buffer);
//     //     return 1;
//     // }
//     // printf("Using device: %s\n", device_name);

//     device_handle = pcap_create(argv[1], error_buffer);
//     if(device_handle == NULL) {
//         printf("%s\n", error_buffer);
//         return 1;
//     }
//     printf("Device handle created.\n");

//     errno = pcap_can_set_rfmon(device_handle);
//     if(errno == 1) {
//         pcap_set_rfmon(device_handle, 1);
//     } else if(errno == 0) {
//         printf("Device does not support monitor mode.\n");
//         return 1;
//     } else if(errno < 0) {
//         printf("Error %i: ", errno);
//         switch(errno) {
//             case PCAP_ERROR_NO_SUCH_DEVICE:
//             printf("No such device.");
//             break;

//             case PCAP_ERROR_PERM_DENIED:
//             printf("Permission denied.");
//             break;

//             case PCAP_ERROR_ACTIVATED:
//             printf("Capture handle has already been activated.");
//             break;

//             case PCAP_ERROR:
//             printf("%s", pcap_geterr(device_handle));
//             break;

//             default:
//             printf("%s", pcap_statustostr(errno));
//             break;
//         }
//         printf("\n");
//         return 1;
//     }
//     printf("Monitor mode set.\n");

//     // errno = pcap_set_snaplen(device_handle, 1);
//     // if(errno != 0) {
//     //     printf("%s\n", pcap_statustostr(errno));
//     //     return 1;
//     // }

//     errno = pcap_set_timeout(device_handle, 5000);
//     if(errno != 0) {
//         printf("%s\n", pcap_statustostr(errno));
//         return 1;
//     }

//     // errno = pcap_set_buffer_size(device_handle, (2*1024*1024));
//     // if(errno != 0) {
//     //     printf("%s\n", pcap_statustostr(errno));
//     //     return 1;
//     // }

//     errno = pcap_activate(device_handle);
//     if(errno < 0) {
//         printf("Error %i: ", errno);
//         switch(errno) {
//             case PCAP_ERROR:
//             printf("%s", pcap_geterr(device_handle));
//             break;

//             default:
//             printf("%s", pcap_statustostr(errno));
//             break;
//         }
//         printf("\n");
//         return 1;
//     }
//     printf("Network device activated successfully.\n");
//     if(errno > 0) {
//         printf("Warning %i:", errno);
//         switch(errno) {
//             case PCAP_WARNING:
//             printf("%s", pcap_geterr(device_handle));
//             break;

//             default:
//             printf("%s", pcap_statustostr(errno));
//             break;
//         }
//         printf("\n");
//     }

//     packet = pcap_next(device_handle, &pcap_header);
//     if(packet == NULL) {
//         printf("No packet grabbed!\n");
//         return 1;
//     }

//     printf("Packet grabbed!\n");
//     printf("Packet length: %d\n", pcap_header.len);
//     printf("Received at: %s", ctime((const time_t*)&pcap_header.ts.tv_sec));
//     printf("Packet:\n");
//     printf("Byte  Hex   Bin\n");
//     for(int i = 0; i < pcap_header.len; i++) {
//         printf("%4i  0x%02x  %s\n", i, packet[i], byte_to_string(packet[i]));
//     }

//     parse(packet);
// }


// void parse(const u_char *packet) {
//     int present;
//     uint8_t version, pad;
//     uint16_t length;
//     uint32_t flags;

//     version = (uint8_t)(packet[0]);
//     pad = (uint8_t)(packet[1]);
//     length = le16toh((uint16_t)(packet[2]));
//     flags = le32toh((uint32_t)(packet[4]));

//     printf("Radiotap header length: %i\n", length);

//     printf("Radiotap flags:\n");

//     for(int i = 0; i < 32; i++) {
//         present = 1;
//         switch((ieee80211_radiotap_type)(i)) {
//             case IEEE80211_RADIOTAP_TSFT:
//                 printf("TSFT");
//                 break;
//             case IEEE80211_RADIOTAP_FLAGS:
//                 printf("Flags");
//                 break;
//             case IEEE80211_RADIOTAP_RATE:
//                 printf("Rate");
//                 break;
//             case IEEE80211_RADIOTAP_CHANNEL:
//                 printf("Channel");
//                 break;
//             case IEEE80211_RADIOTAP_FHSS:
//                 printf("FHSS");
//                 break;
//             case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
//                 printf("dBm Antenna Signal");
//                 break;
//             case IEEE80211_RADIOTAP_DBM_ANTNOISE:
//                 printf("dBm Antenna Noise");
//                 break;
//             case IEEE80211_RADIOTAP_LOCK_QUALITY:
//                 printf("Lock Quality");
//                 break;
//             case IEEE80211_RADIOTAP_TX_ATTENUATION:
//                 printf("Tx Attenuation");
//                 break;
//             case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
//                 printf("dB Tx Attenuation");
//                 break;
//             case IEEE80211_RADIOTAP_DBM_TX_POWER:
//                 printf("dBm Tx Power");
//                 break;
//             case IEEE80211_RADIOTAP_ANTENNA:
//                 printf("Antenna");
//                 break;
//             case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
//                 printf("dB Antenna Signal");
//                 break;
//             case IEEE80211_RADIOTAP_DB_ANTNOISE:
//                 printf("dB Antenna Noise");
//                 break;
//             case IEEE80211_RADIOTAP_RX_FLAGS:
//                 printf("Rx Flags");
//                 break;
//             case IEEE80211_RADIOTAP_TX_FLAGS:
//                 printf("Tx Flags");
//                 break;
//             case IEEE80211_RADIOTAP_RTS_RETRIES:
//                 printf("RTS Retries");
//                 break;
//             case IEEE80211_RADIOTAP_DATA_RETRIES:
//                 printf("Data Retries");
//                 break;
//             case IEEE80211_RADIOTAP_MCS:
//                 printf("MCS Information");
//                 break;
//             case IEEE80211_RADIOTAP_AMPDU_STATUS:
//                 printf("A-MPDU Status");
//                 break;
//             case IEEE80211_RADIOTAP_VHT:
//                 printf("VHT Information");
//                 break;
//             case IEEE80211_RADIOTAP_TIMESTAMP:
//                 printf("Timestamp");
//                 break;
//             case IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE:
//                 printf("Radiotap Namespace");
//                 break;
//             case IEEE80211_RADIOTAP_VENDOR_NAMESPACE:
//                 printf("Vender Namespace");
//                 break;
//             case IEEE80211_RADIOTAP_EXT:
//                 printf("Ext");
//                 break;
//             default:
//                 present = 0;
//                 break;
//         }

//         if(present) {
//             printf(": ");
//             if((flags >> i) & 0x1) {
//                 printf("present");
//             } else {
//                 printf("absent");
//             }
//             printf("\n");
//         }
//     }
// }


// char * byte_to_string(uint8_t byte) {
//     int i;
//     static char string[9];

//     for(i = 0; i < 8; i++) {
//         if(i > 3) {
//             if(i == 4) string[i] = ' ';
//             string[i+1] = ((byte >> (7 - i)) & 0x1) + '0';
//         } else {
//             string[i] = ((byte >> (7 - i)) & 0x1) + '0';
//         }
//     }

//     return string;
// }