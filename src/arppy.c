#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#include "arppy.h"

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
    int len, sock, expected, offset;
    uint8_t *raw;
    arp_packet *arp;
    frame_hdr *frame;
    struct sockaddr_ll addr;
    char srcip[32], srcmac[32], dstip[32], dstmac[32];
    char *ifname = 0;
    unsigned int ifindex = 0;

    arguments.verbose = 0;
    arguments.config = 0;
    
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    printf("INTERFACE=%s, IPS=%s\n", arguments.args[0], arguments.args[1]);

    raw = malloc(sizeof(uint8_t) * IP_MAXPACKET);
    memset(raw, 0, sizeof(uint8_t) * IP_MAXPACKET);

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

    // TODO: Convert IP's to array of addrins
    // count ,'s in array to get count
    // malloc array of unsigned longs count of , + 1
    // strtok loop
    // inet_pton, AF_INET, in_addr
    // access in_addr.s_addr as unsigned long and store

    // Bind to the interface
    memset(&addr, 0, sizeof(addr));
    addr.sll_ifindex = if_nametoindex(arguments.args[0]);
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr))) {
        perror("failed to bind to interface");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // TODO: Get ineterface mac address
    // struct ifreq, ifr_name = ifname
    // ioctl(sock, SIOCGIFHWADDR, &ifreq
    // s.ifr_addr.sa_data, store 6 bytes for re-use

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

    // Pre-calculate some things for efficiency
    expected = sizeof(arp_packet) + sizeof(frame_hdr);
    offset = sizeof(frame_hdr);

    // Keep looping on each packet until there's an error
    while ((len =  recv(sock, raw, IP_MAXPACKET, 0)) != -1) {

        // Sanity check and shortcut out
        if (len != expected)
            continue;
        
        // Find the payload parts
        frame = (frame_hdr *) raw;
        arp = (arp_packet *) (raw + sizeof(frame_hdr));

        // Check for the frame type to ensure it's ARP
        if (ntohs(frame->type) != ETHERTYPE_ARP) {
            printf("Not an ARP (%#06x)\n", ntohs(frame->type));
            continue;
        }

        // If it's a request, we need to validate that it's in our list of IP's to generate a reply
        if (ntohs(arp->op) == ARP_REQ) {
            printf("Request: Who has %s (%s),",
                print_ip(arp->target_ip, dstip, sizeof(dstip)), 
                print_mac(arp->target_mac, dstmac, sizeof(dstmac)));
            printf(" tell %s (%s)\n", 
                print_ip(arp->sender_ip, srcip, sizeof(srcip)),
                print_mac(arp->sender_mac, srcmac, sizeof(srcmac)));
            // TODO: Check incoming target_ip vs list of ip's
            // TODO: Generate a reply with the if's mac and the sender's info
            // TODO: ethernet frame, with arp reply inside, call send
        } else {
            // TODO: Don't do much with replies
            printf("Reply: Tell %s (%s),", 
                print_ip(arp->target_ip, dstip, sizeof(dstip)), 
                print_mac(arp->target_mac, dstmac, sizeof(dstmac)));
            printf(" %s is at %s\n",
                print_ip(arp->sender_ip, srcip, sizeof(srcip)),
                print_mac(arp->sender_mac, srcmac, sizeof(srcmac)));
        }
    }

    close(sock);
    free(frame);

    return EXIT_SUCCESS;
}

const char * print_ip(uint8_t ip[4], char *buffer, int length) {
    // xxx.xxx.xxx.xxx
    memset(buffer, 0, length);

    snprintf(buffer, length - 1, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buffer;
}

const char * print_mac(uint8_t mac[6], char *buffer, int length) {
    // xx.xx.xx.xx.xx.xx
    memset(buffer, 0, length);

    snprintf(buffer, length - 1, "%02x%02x.%02x%02x.%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buffer;
}