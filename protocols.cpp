#include <arpa/inet.h>
#include <vector>
#include <cstring>
#include "protocols.h"

struct full_arp_packet *create_arp_packet(const std::vector<uint8_t> &srchw, const std::vector<uint8_t> &srcpr,
                                          const std::vector<uint8_t> &dsthw, const std::vector<uint8_t> &dstpr)
{
    struct full_arp_packet *packet = new full_arp_packet{};
    setup_ethernet_header(packet->eth, dsthw, srchw, ETHERNET_TYPE_ARP);
    packet->htype = htons(HARDWARE_TYPE_ETHERNET);
    packet->ptype = htons(PROTOCOL_TYPE_IPv4);
    packet->hlen = HARDWARE_ADDR_LEN;
    packet->plen = IP_ADDR_LEN;
    packet->opcode = htons(ARP_REQUEST);
    std::memcpy(packet->srchw, srchw.data(), HARDWARE_ADDR_LEN);
    std::memcpy(packet->srcpr, srcpr.data(), IP_ADDR_LEN);
    std::memcpy(packet->dsthw, dsthw.data(), HARDWARE_ADDR_LEN);
    std::memcpy(packet->dstpr, dstpr.data(), IP_ADDR_LEN);
    return packet;
}

void setup_ethernet_header(ethernet_header &eth, const std::vector<uint8_t> &dst, const std::vector<uint8_t> &src, uint16_t type)
{
    std::memcpy(eth.dst, dst.data(), HARDWARE_ADDR_LEN);
    std::memcpy(eth.src, src.data(), HARDWARE_ADDR_LEN);
    eth.type = htons(type);
}
