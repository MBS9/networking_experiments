#include <arpa/inet.h>
#include <vector>
#include <cstring>
#include <stdexcept>
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

std::vector<uint8_t> get_mac_from_arp(const full_arp_packet *arp_response)
{
    if (ntohs(arp_response->opcode) != ARP_REPLY)
    {
        throw std::runtime_error("Received packet is not an ARP reply.");
    }
    return std::vector<uint8_t>(arp_response->srchw, arp_response->srchw + HARDWARE_ADDR_LEN);
}

void setup_ethernet_header(ethernet_header &eth, const std::vector<uint8_t> &dst, const std::vector<uint8_t> &src, uint16_t type)
{
    std::memcpy(eth.dst, dst.data(), HARDWARE_ADDR_LEN);
    std::memcpy(eth.src, src.data(), HARDWARE_ADDR_LEN);
    eth.type = htons(type);
}
