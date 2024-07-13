#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#include "autoconf.h"
#include "arppy.h"

#define IPTOKEN ",;"


struct sock_filter arp_filter[] = {
    { 0x28, 0, 0, 0x0000000c }, // ldh [12]
    { 0x15, 0, 1, 0x00000806 }, // jeq 0x0806
    { 0x6, 0, 0, 0x00040000 },  // return 1
    { 0x6, 0, 0, 0x00000000 }   // return 0
};

const char *argp_program_version = "arppy 1.0";
const char *argp_program_bug_address = "keetfox@gmail.com";
const char doc[] = "Arp responder for limited proxy-arping";
static char arg_doc[] = "INTERFACE IPS";

static struct argp_option options[] = {
    {"verbose",     'v',    0,              0,  "Verbose output"},
    {"config",      'c',    "FILE",         0,  "Configuration file"},
    { 0 }
};

struct arguments {
    char *args[2];
    int verbose;
    char *config;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
        case 'v':
            arguments->verbose = 1;
            break;
        case 'c':
            arguments->config = arg;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 2)
                argp_usage(state);

            arguments->args[state->arg_num] = arg;
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 2)
                argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = { options, parse_opt, arg_doc, doc };
struct arguments arguments;

int main(int argc, char **argv) {
    int sock;
    char srcip[32], srcmac[32], dstip[32], dstmac[32];
    unsigned long *checkips = NULL;
    unsigned int ipcount = 0;
    unsigned int ifindex = 0;
    uint8_t ifmac[6];

    arguments.verbose = 0;
    arguments.config = 0;
    
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Parse the IP addresses
    char *token = strtok(arguments.args[1], IPTOKEN);
    while (token != NULL) {
        struct in_addr addr;
        if (inet_pton(AF_INET, token, &addr) != 1) {
            fprintf(stderr, "cannot parse ip address: %s\n", token);
            exit(EXIT_FAILURE);
        }

        if (checkips == NULL) {
            checkips = malloc(sizeof(unsigned long));
            ipcount = 1;
        } else {
            unsigned long *iptemp = malloc(sizeof(unsigned long) * (ipcount + 1));
            memmove(iptemp, checkips, sizeof(unsigned long) * ipcount);
            free(checkips);
            checkips = iptemp;
            ipcount++;
        }
        printf("Parsed %x\n", addr.s_addr);
        checkips[ipcount - 1] = addr.s_addr;
        token = strtok(NULL, IPTOKEN);
    }

    // Create a raw socket
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("failed to get socket");
        exit(EXIT_FAILURE);
    }

    // Get interface to bind to
    if ((ifindex = if_nametoindex(arguments.args[0])) == 0) {
        perror("failed to get interface");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Bind to the interface
    struct sockaddr_ll bindaddr;    
    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sll_ifindex = if_nametoindex(arguments.args[0]);
    bindaddr.sll_family = AF_PACKET;
    bindaddr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) {
        perror("failed to bind to interface");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Get our interface MAC for later use
    struct ifreq req;
    strcpy(req.ifr_name, arguments.args[0]);
    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
        perror("could not get hardware address");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 6; i++) {
        ifmac[i] = req.ifr_addr.sa_data[i];
    }

    if (arguments.verbose)
        printf("%s MAC: %s\n", arguments.args[0], print_mac(ifmac, dstmac, sizeof(dstmac)));

    // Create a BPF for only ARP packets
    struct sock_fprog bpf = {
        .len = sizeof(arp_filter) / sizeof(*arp_filter),
        .filter = arp_filter
    };

    // Attach the filter to the socket
    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
        perror("failed to set bpf filter");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Allocate our raw packet
    uint8_t *raw = malloc(sizeof(uint8_t) * IP_MAXPACKET);
    memset(raw, 0, sizeof(uint8_t) * IP_MAXPACKET);

    // Pre-calculate some things for efficiency
    int expected = sizeof(arp_packet) + sizeof(frame_hdr);
    int offset = sizeof(frame_hdr);

    // Keep looping on each packet until there's an error
    int len = 0;
    while ((len =  recv(sock, raw, IP_MAXPACKET, 0)) != -1) {

        // Sanity check and shortcut out
        if (len != expected)
            continue;
        
        // Find the payload parts
        frame_hdr *frame = (frame_hdr *) raw;
        arp_packet *arp = (arp_packet *) (raw + sizeof(frame_hdr));

        // Check for the frame type to ensure it's ARP
        if (ntohs(frame->type) != ETHERTYPE_ARP) {
            printf("Not an ARP (%#06x)\n", ntohs(frame->type));
            continue;
        }

        // If it's a request, we need to validate that it's in our list of IP's to generate a reply
        if (ntohs(arp->op) == ARP_REQ) {
            if (arguments.verbose) {
                printf("Request: Who has %s (%s),",
                    print_ip(arp->target_ip, dstip, sizeof(dstip)), 
                    print_mac(arp->target_mac, dstmac, sizeof(dstmac)));
                printf(" tell %s (%s)\n", 
                    print_ip(arp->sender_ip, srcip, sizeof(srcip)),
                    print_mac(arp->sender_mac, srcmac, sizeof(srcmac)));
            }
            // Convert target IP into an unsigned long
            unsigned long targetip = arp->target_ip[0] | arp->target_ip[1] << 8 | arp->target_ip[2] << 16 | arp->target_ip[3] << 24;
            for (int i = 0; i < ipcount; i++) {
                if (targetip == checkips[i]) {
                    if (arguments.verbose) {
                        printf("Match\n");
                        // TODO: ethernet frame, with arp reply inside, call send
                    }
                    break;
                }
            }

            
        } else {
            // TODO: Don't do much with replies
            if (arguments.verbose) {
                printf("Reply: Tell %s (%s),", 
                    print_ip(arp->target_ip, dstip, sizeof(dstip)), 
                    print_mac(arp->target_mac, dstmac, sizeof(dstmac)));
                printf(" %s is at %s\n",
                    print_ip(arp->sender_ip, srcip, sizeof(srcip)),
                    print_mac(arp->sender_mac, srcmac, sizeof(srcmac)));
            }
        }
    }

    close(sock);
    free(raw);
    free(checkips);

    return EXIT_SUCCESS;
}

const char * print_ip(uint8_t ip[4], char *buffer, int length) {
    // xxx.xxx.xxx.xxx
    memset(buffer, 0, length);

    snprintf(buffer, length - 1, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buffer;
}

const char * print_mac(uint8_t mac[6], char *buffer, int length) {
    // xxxx.xxxx.xxxx
    memset(buffer, 0, length);

    snprintf(buffer, length - 1, "%02x%02x.%02x%02x.%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buffer;
}