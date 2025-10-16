// Thank you https://wiki.osdev.org/Address_Resolution_Protocol
#include <cstdint>
#include <vector>

#define ETHERNET_TYPE_ARP 0x0806
#define HARDWARE_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct ethernet_header
{
    uint8_t dst[HARDWARE_ADDR_LEN]; // Destination MAC address
    uint8_t src[HARDWARE_ADDR_LEN]; // Source MAC address
    uint16_t type;                  // EtherType
} __attribute__((packed));

#define ARP_REQUEST 1
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

struct full_arp_packet *create_arp_packet(const std::vector<uint8_t> &srchw, const std::vector<uint8_t> &srcpr,
                                          const std::vector<uint8_t> &dsthw, const std::vector<uint8_t> &dstpr);
void setup_ethernet_header(ethernet_header &eth, const std::vector<uint8_t> &dst, const std::vector<uint8_t> &src, uint16_t type);
