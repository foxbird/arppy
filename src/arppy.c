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
    {"verbose",     'v',    0,              0,  "Verbose output (specify multiple times for more verbosity)"},
    {"config",      'c',    "FILE",         0,  "Configuration file"},
    {"mac",         'm',    "MACADDRSS",    0,  "MAC to send (eeee.eeee.eeee)"},
    {"dry-run",     'd',    0,              0,  "Do not send arp replies"},
    { 0 }
};

struct arguments {
    char *ifname;
    char *config;
    int verbose;
    int use_interface_mac;
    uint8_t mac[MAC_BYTE_LENGTH];
    unsigned long *handleips;
    unsigned int handle_ip_count;
    int send_replies;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
        case 'v':
            arguments->verbose++;
            break;
        case 'c':
            arguments->config = arg;
            break;
        case 'd':
            arguments->send_replies = 0;
            break;
        case 'm':
            if (EXIT_SUCCESS == parse_mac_address(arg, arguments->mac)) {
                arguments->use_interface_mac = 0;
            } else {
                argp_usage(state);
            }
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num >= 2)
                argp_usage(state);

            if (state->arg_num == 0) {
                arguments->ifname = arg;
            } else {
                if ((arguments->handleips = parse_ip_list(arg, &arguments->handle_ip_count)) == NULL) {
                    argp_usage(state);
                }
            }
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

int parse_mac_address(char *arg, uint8_t mac[MAC_BYTE_LENGTH]) {
    if (strlen(arg) != MAC_STRING_LENGTH) {
        fprintf(stderr, "cannot parse mac address %s\n", arg);
        return EXIT_FAILURE;
    }
    char *token = strtok(arg, ".");
    int maccount = 0;
    while (token != NULL) {
        if (strlen(token) != MAC_SEGMENT_LENGTH) {
            fprintf(stderr, "cannot parse mac address %s [%s]\n", arg, token);
            return EXIT_FAILURE;
        }
        uint16_t part = strtoul(token, NULL, HEX_DECIMAL_BASE);
        mac[maccount++] = (part >> 8) & WORD_MASK;
        mac[maccount++] = part & BYTE_MASK;
        token = strtok(NULL, ".");
    }
    return EXIT_SUCCESS;
}

unsigned long *parse_ip_list(char *arg, int *count) {
    unsigned long *result = NULL;

    // Parse the IP addresses
    char *token = strtok(arg, IPTOKEN);
    while (token != NULL) {
        struct in_addr addr;
        if (inet_pton(AF_INET, token, &addr) != 1) {
            fprintf(stderr, "cannot parse ip address: %s\n", token);
            return 0;
        }

        if (result == NULL) {
            result = malloc(sizeof(unsigned long));
            *count = 1;
        } else {
            unsigned long *iptemp = malloc(sizeof(unsigned long) * ((*count) + 1));
            memmove(iptemp, result, sizeof(unsigned long) * (*count));
            free(result);
            result = iptemp;
            (*count)++;
        }
        
        result[(*count) - 1] = addr.s_addr;
        token = strtok(NULL, IPTOKEN);
    }

    return result;
}

void print_ip_list(unsigned long *list, unsigned int count) {
    for (int i = 0; i < count; i++) {
        printf("Listening for IP %lu.%lu.%lu.%lu\n", 
            list[i] & BYTE_MASK, 
            list[i] >> 8 & BYTE_MASK,
            list[i] >> 16 & BYTE_MASK,
            list[i] >> 24 & BYTE_MASK);
    }
}

socktype_t create_socket(char *ifname) {
    socktype_t sock;
    // Create a raw socket
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("failed to get socket");
        exit(EXIT_FAILURE);
    }

    // Get interface to bind to
    unsigned int ifindex = 0;
    if ((ifindex = if_nametoindex(ifname)) == 0) {
        perror("failed to get interface");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Bind to the interface
    struct sockaddr_ll bindaddr;    
    memset(&bindaddr, 0, sizeof(bindaddr));
    bindaddr.sll_ifindex = if_nametoindex(ifname);
    bindaddr.sll_family = AF_PACKET;
    bindaddr.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock, (struct sockaddr *) &bindaddr, sizeof(bindaddr))) {
        perror("failed to bind to interface");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

void set_source_mac(socktype_t sock, char *ifname, char mac[MAC_BYTE_LENGTH], int set_from_interface, int verbose) {
    if (set_from_interface) {        
        struct ifreq req;
        strcpy(req.ifr_name, ifname);
        if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
            perror("could not get hardware address");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < MAC_BYTE_LENGTH; i++) {
            mac[i] = req.ifr_addr.sa_data[i];
        }
    }

    if (verbose) {
        char macbuf[MAC_PRINT_BUFFER];        
        printf("mac address for replies: %s\n", print_mac(mac, macbuf, sizeof(macbuf)));
    }

}

void set_bpf_filter(socktype_t sock, int verbose) {
    if (verbose)
        printf("setting bpf filter for data\n");

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
}

void print_arp_request(arp_packet *arp) {
    char ipbuffer[IP_PRINT_BUFFER];
    char macbuffer[MAC_PRINT_BUFFER];
    printf("Request: Who has %s,",
        print_ip(arp->dst_ip, ipbuffer, sizeof(ipbuffer)));
    printf(" tell %s (%s)\n", 
        print_ip(arp->src_ip, ipbuffer, sizeof(ipbuffer)),
        print_mac(arp->src_mac, macbuffer, sizeof(macbuffer)));
}

void print_arp_reply(arp_packet *arp) {
    char ipbuffer[IP_PRINT_BUFFER];
    char macbuffer[MAC_PRINT_BUFFER];
    printf("Reply: Tell %s (%s),", 
        print_ip(arp->dst_ip, ipbuffer, sizeof(ipbuffer)), 
        print_mac(arp->dst_mac, macbuffer, sizeof(macbuffer)));
    printf(" %s is at %s\n",
        print_ip(arp->src_ip, ipbuffer, sizeof(ipbuffer)),
        print_mac(arp->src_mac, macbuffer, sizeof(macbuffer)));

}

int check_ip_handled(uint8_t ip[IP_BYTE_LENGTH], unsigned long *iplist, unsigned int ipcount) {
    // Convert target IP into an unsigned long
    unsigned long targetip = ip[0] | ip[1] << 8 | ip[2] << 16 | ip[3] << 24;

    // Check the target IP against the ones we're handling
    for (int i = 0; i < ipcount; i++) {
        if (targetip == iplist[i]) {
            return 1;
        }
    }

    return 0;

}

void create_arp_reply(
    uint8_t srcmac[MAC_BYTE_LENGTH], 
    uint8_t srcip[IP_BYTE_LENGTH], 
    uint8_t dstmac[MAC_BYTE_LENGTH], 
    uint8_t dstip[IP_BYTE_LENGTH], 
    uint8_t *buffer) 
{
    // Create a reply frame
    frame_hdr *hdr = (frame_hdr *) buffer;
    arp_packet *arp = (arp_packet *) (buffer + sizeof(frame_hdr));

    // Set the other attributes
    hdr->type = htons(ETHERTYPE_ARP);
    arp->htype = htons(ARP_HTYPE_ETHERNET);
    arp->ptype = htons(ARP_PTYPE_IP);
    arp->hlen = ETHER_ADDR_LEN;
    arp->plen = sizeof(in_addr_t);
    arp->op = htons(ARP_REP);

    // Copy in the MAC addresses
    for (int i = 0; i < MAC_BYTE_LENGTH; i++) {
        hdr->src[i] = srcmac[i];
        arp->src_mac[i] = srcmac[i];
        hdr->dst[i] = dstmac[i];
        arp->dst_mac[i] = dstmac[i];
    }

    // Copy in the IP addresses
    for (int i = 0; i < IP_BYTE_LENGTH; i++) {
        arp->src_ip[i] = srcip[i];
        arp->dst_ip[i] = dstip[i];
    }
}

const char * print_ip(uint8_t ip[IP_BYTE_LENGTH], char *buffer, int length) {
    // xxx.xxx.xxx.xxx
    memset(buffer, 0, length);

    snprintf(buffer, length - 1, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buffer;
}

const char * print_mac(uint8_t mac[MAC_BYTE_LENGTH], char *buffer, int length) {
    // xxxx.xxxx.xxxx
    memset(buffer, 0, length);

    snprintf(buffer, length - 1, "%02x%02x.%02x%02x.%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buffer;
}

static struct argp argp = { options, parse_opt, arg_doc, doc };
struct arguments arguments;

int main(int argc, char **argv) {
    socktype_t sock;

    // Zero the arguments
    arguments.verbose = 0;
    arguments.config = 0;
    arguments.use_interface_mac = 1;
    arguments.send_replies = 1;
    arguments.handleips = 0;
    arguments.handle_ip_count = 0;

    // Parse the arguments    
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    if (arguments.verbose)
        printf("verbosity: %d\n", arguments.verbose);

    // Create the socket and bind it
    sock = create_socket(arguments.ifname);

    // Print the addresses we listen for
    if (arguments.verbose)
        print_ip_list(arguments.handleips, arguments.handle_ip_count);

    // Set the source mac for replies
    set_source_mac(sock, arguments.ifname, arguments.mac, arguments.use_interface_mac, arguments.verbose);

    // Set the BPF filter
    set_bpf_filter(sock, arguments.verbose);

    // Allocate our raw packet
    uint8_t *raw = malloc(sizeof(uint8_t) * IP_MAXPACKET);
    memset(raw, 0, sizeof(uint8_t) * IP_MAXPACKET);

    // Keep looping on each packet until there's an error
    int len = 0;
    while ((len =  recv(sock, raw, IP_MAXPACKET, 0)) != -1) {
        // Find the payload parts
        frame_hdr *frame = (frame_hdr *) raw;
        arp_packet *arp_request = (arp_packet *) (raw + sizeof(frame_hdr));

        // Check for the frame type to ensure it's ARP
        if (ntohs(frame->type) != ETHERTYPE_ARP) {
            printf("Error: Not an ARP (%#06x)\n", ntohs(frame->type));
            continue;
        }

        // If it's a request, we need to validate that it's in our list of IP's to generate a reply
        if (ntohs(arp_request->op) == ARP_REQ) {
            if (arguments.verbose >= VERBOSITY_HIGH)
                print_arp_request(arp_request);

            if (check_ip_handled(arp_request->dst_ip, arguments.handleips, arguments.handle_ip_count)) {
                static uint8_t reply[sizeof(frame_hdr) + sizeof(arp_packet)];
                create_arp_reply(arguments.mac, arp_request->dst_ip, arp_request->src_mac, arp_request->src_ip, reply);
                if (arguments.verbose >= VERBOSITY_HIGH) { 
                    printf("Send ");
                    print_arp_reply((arp_packet*) (reply + sizeof(frame_hdr)));
                }

                if (arguments.send_replies) {
                    if (write(sock, reply, sizeof(reply)) < 0) {
                        perror("could not write reply");
                        exit(EXIT_FAILURE);
                    }
                }
            }
            
        } else {
            if (arguments.verbose >= VERBOSITY_VERYHIGH) 
                print_arp_reply(arp_request);
        }
    }

    close(sock);
    free(raw);
    free(arguments.handleips);

    return EXIT_SUCCESS;
}
