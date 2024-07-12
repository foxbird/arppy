#ifndef _ARPPY_H_
#define _ARPPY_H_

#include <net/ethernet.h>

#define ARP_REQ 1
#define ARP_REP 2

const char * print_ip(uint8_t ip[4], char buffer[], int len);
const char * print_mac(uint8_t mac[6], char buffer[], int len);

typedef struct _arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} arp_packet;

typedef struct _eth_frame_hdr {
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
} frame_hdr;


#endif