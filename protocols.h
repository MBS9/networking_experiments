// Thank you https://wiki.osdev.org/Address_Resolution_Protocol
#include <cstdint>
#include <vector>
#include <memory>

#define MAC_BROADCAST {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define ETHERNET_TYPE_ARP 0x0806
#define ETHERNET_TYPE_IPV4 0x0800
#define HARDWARE_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define MAX_ETHERNET_FRAME_SIZE 1518
#define IP_PROTOCOL_UDP 17
#define IP_PROTOCOL_ICMP 1

struct ethernet_header
{
    uint8_t dst[HARDWARE_ADDR_LEN]; // Destination MAC address
    uint8_t src[HARDWARE_ADDR_LEN]; // Source MAC address
    uint16_t type;                  // EtherType
} __attribute__((packed));

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define HARDWARE_TYPE_ETHERNET 1
#define PROTOCOL_TYPE_IPv4 0x0800

struct full_arp_packet
{
    ethernet_header eth;              // Ethernet header
    uint16_t htype;                   // Hardware type
    uint16_t ptype;                   // Protocol type
    uint8_t hlen;                     // Hardware address length (Ethernet = 6)
    uint8_t plen;                     // Protocol address length (IPv4 = 4)
    uint16_t opcode;                  // ARP Operation Code
    uint8_t srchw[HARDWARE_ADDR_LEN]; // Source hardware address - hlen bytes (see above)
    uint8_t srcpr[IP_ADDR_LEN];       // Source protocol address - plen bytes (see above). If IPv4 can just be a "u32" type.
    uint8_t dsthw[HARDWARE_ADDR_LEN]; // Destination hardware address - hlen bytes (see above)
    uint8_t dstpr[IP_ADDR_LEN];       // Destination protocol address - plen bytes (see above). If IPv4 can just be a "u32" type.
} __attribute__((packed));

struct ip_header
{
    ethernet_header eth;            // Ethernet header
    uint8_t version_ihl;            // Version and Internet Header Length
    uint8_t tos;                    // Type of Service
    uint16_t total_length;          // Total Length
    uint16_t identification;        // Identification
    uint16_t flags_fragment_offset; // Flags and Fragment Offset
    uint8_t ttl;                    // Time to Live
    uint8_t protocol;               // Protocol
    uint16_t header_checksum;       // Header Checksum
    uint32_t src_ip;                // Source IP Address
    uint32_t dst_ip;                // Destination IP Address
} __attribute__((packed));

struct udp_header
{
    ip_header ip;      // Ip header
    uint16_t src_port; // Source port
    uint16_t dst_port; // Destination port
    uint16_t length;   // Length of UDP header and payload
    uint16_t checksum; // Checksum
    char data[];
} __attribute__((packed));

struct icmp
{
    ip_header ip;
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t extended_header;
    char data[];
} __attribute__((packed));

#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ECHO_REPLY 0

std::unique_ptr<full_arp_packet> create_arp_packet(const std::vector<uint8_t> &srchw, const std::vector<uint8_t> &srcpr,
                                                   const std::vector<uint8_t> &dsthw, const std::vector<uint8_t> &dstpr,
                                                   const uint16_t opcode);
std::vector<uint8_t> get_mac_from_arp(const full_arp_packet *arp_response);

void setup_ethernet_header(ethernet_header &eth, const std::vector<uint8_t> &dst, const std::vector<uint8_t> &src, uint16_t type);

void setup_ip_header(ip_header &ip, uint8_t protocol, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, uint16_t total_length);

void setup_udp_header(udp_header &udp, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, uint16_t length,
                      uint16_t dst_port, uint16_t src_port);
std::unique_ptr<icmp> icmp_ping_reply(icmp &msg, unsigned int buf_len);
