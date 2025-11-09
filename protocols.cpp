#include <arpa/inet.h>
#include <vector>
#include <cstring>
#include <stdexcept>
#include "protocols.h"
#include "main.h"

struct full_arp_packet *create_arp_packet(const std::vector<uint8_t> &srchw, const std::vector<uint8_t> &srcpr,
                                          const std::vector<uint8_t> &dsthw, const std::vector<uint8_t> &dstpr,
                                          const uint16_t opcode)
{
    struct full_arp_packet *packet = new full_arp_packet{};
    setup_ethernet_header(packet->eth, dsthw, srchw, ETHERNET_TYPE_ARP);
    packet->htype = htons(HARDWARE_TYPE_ETHERNET);
    packet->ptype = htons(PROTOCOL_TYPE_IPv4);
    packet->hlen = HARDWARE_ADDR_LEN;
    packet->plen = IP_ADDR_LEN;
    packet->opcode = htons(opcode);
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

void setup_ip_header(ip_header &ip, uint8_t protocol, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, uint16_t total_length)
{
    ip.version_ihl = (4 << 4) | (sizeof(ip_header) - sizeof(ethernet_header)) / 4;
    ip.tos = 0;
    ip.total_length = htons(total_length + (sizeof(ip_header) - sizeof(ethernet_header)));
    ip.identification = 0;
    ip.flags_fragment_offset = htons((1 << 14));
    ip.ttl = 255;
    ip.protocol = protocol;
    memcpy(&ip.dst_ip, dst_ip.data(), sizeof(ip.dst_ip));
    memcpy(&ip.src_ip, src_ip.data(), sizeof(ip.src_ip));
    int total = 0;
    uint8_t *header = reinterpret_cast<uint8_t *>(&ip);
    for (int i = sizeof(ethernet_header); i + 1 < (sizeof(ip_header) - sizeof(ethernet_header)); i = i + 2)
    {
        total += (header[i] << 8) | header[i + 1];
    }
    while (total > 0xFFFF)
    {
        total = (total >> 8) + (total & 0xFFFF);
    }
    total = ~total;
    ip.header_checksum = htons(total);
    std::vector<uint8_t> target_mac = arp_lookup(dst_ip);
    setup_ethernet_header(ip.eth, target_mac, PRETEND_MAC, ETHERNET_TYPE_IPV4);
}

void setup_udp_header(udp_header &udp, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, uint16_t length,
                      uint16_t dst_port, uint16_t src_port)
{
    setup_ip_header(udp.ip, 17, src_ip, dst_ip, length + sizeof(udp_header) - sizeof(ip_header));
    udp.dst_port = htons(dst_port);
    udp.src_port = htons(src_port);
}