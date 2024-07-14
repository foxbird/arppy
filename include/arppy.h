#ifndef _ARPPY_H_
#define _ARPPY_H_

#include <net/ethernet.h>

#define ARP_REQ 1
#define ARP_REP 2

#define ARP_HTYPE_ETHERNET 1
#define ARP_PTYPE_IP ETHERTYPE_IP

#define VERBOSITY_NONE 0
#define VERBOSITY_LOW 1
#define VERBOSITY_HIGH 2
#define VERBOSITY_VERYHIGH 3

#define MAC_BYTE_LENGTH 6
#define MAC_STRING_LENGTH 14
#define MAC_SEGMENT_LENGTH 4
#define IP_BYTE_LENGTH  4

#define HEX_DECIMAL_BASE 16

#define WORD_MASK 0xFFFF
#define BYTE_MASK 0xFF

#define IP_PRINT_BUFFER 32
#define MAC_PRINT_BUFFER 32

typedef int socktype_t;

typedef struct _arp_packet {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    uint8_t src_mac[6];
    uint8_t src_ip[4];
    uint8_t dst_mac[6];
    uint8_t dst_ip[4];
} arp_packet;

typedef struct _eth_frame_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} frame_hdr;

const char * print_ip(uint8_t ip[IP_BYTE_LENGTH], char buffer[], int len);
const char * print_mac(uint8_t mac[MAC_BYTE_LENGTH], char buffer[], int len);
static error_t parse_opt(int key, char *arg, struct argp_state *state);
int parse_mac_address(char *arg, uint8_t mac[MAC_BYTE_LENGTH]);
unsigned long *parse_ip_list(char *arg, int *count);
void print_ip_list(unsigned long *list, unsigned int count);
socktype_t create_socket(char *ifname);
void set_source_mac(socktype_t sock, char *ifname, char mac[MAC_BYTE_LENGTH], int set_from_interface, int verbose);
void set_bpf_filter(socktype_t sock, int verbose);
void print_arp_request(arp_packet *arp);
void print_arp_reply(arp_packet *arp);
int check_ip_handled(uint8_t ip[IP_BYTE_LENGTH], unsigned long *iplist, unsigned int ipcount);
void create_arp_reply(uint8_t srcmac[MAC_BYTE_LENGTH], uint8_t srcip[IP_BYTE_LENGTH], uint8_t dstmac[MAC_BYTE_LENGTH], uint8_t dstip[IP_BYTE_LENGTH], uint8_t *buffer);



#endif