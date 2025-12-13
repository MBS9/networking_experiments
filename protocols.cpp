#include <arpa/inet.h>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <memory>
#include "protocols.h"
#include "main.h"

std::unique_ptr<full_arp_packet> create_arp_packet(const std::vector<uint8_t> &srchw, const std::vector<uint8_t> &srcpr,
                                                   const std::vector<uint8_t> &dsthw, const std::vector<uint8_t> &dstpr,
                                                   const uint16_t opcode)
{
    auto packet = std::make_unique<full_arp_packet>();
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

void finish_checksum(unsigned int *total, uint16_t *data, unsigned int len)
{
    for (int i = 0; i < len / 2; i++)
    {
        *total += ntohs(data[i]);
    }
    while (*total >> 16)
    {
        *total = (*total >> 16) + (*total & 0xFFFF);
    }
    *total = ~*total;
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
    ip.header_checksum = 0;
    memcpy(&ip.dst_ip, dst_ip.data(), sizeof(ip.dst_ip));
    memcpy(&ip.src_ip, src_ip.data(), sizeof(ip.src_ip));
    unsigned int total = 0;
    uint16_t *header = reinterpret_cast<uint16_t *>(&ip.version_ihl);
    finish_checksum(&total, header, sizeof(ip_header) - sizeof(ethernet_header));
    ip.header_checksum = htons(static_cast<uint16_t>(total));
    std::vector<uint8_t> target_mac = arp_lookup(dst_ip);
    setup_ethernet_header(ip.eth, target_mac, PRETEND_MAC, ETHERNET_TYPE_IPV4);
}

void setup_udp_header(udp_header &udp, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, uint16_t length,
                      uint16_t dst_port, uint16_t src_port)
{
    uint16_t udp_len = length + sizeof(udp_header) - sizeof(ip_header);
    setup_ip_header(udp.ip, IP_PROTOCOL_UDP, src_ip, dst_ip, udp_len);
    udp.dst_port = htons(dst_port);
    udp.src_port = htons(src_port);
    udp.length = htons(udp_len);
    udp.checksum = 0;
    unsigned int total = 0;
    total += (src_ip[0] << 8) | src_ip[1];
    total += (src_ip[2] << 8) | src_ip[3];
    total += (dst_ip[0] << 8) | dst_ip[1];
    total += (dst_ip[2] << 8) | dst_ip[3];
    total += IP_PROTOCOL_UDP;
    total += udp_len;
    int i;
    for (i = 0; i < length - 1; i += 2)
    {
        total += (udp.data[i] << 8) | udp.data[i + 1];
    }
    if (length % 2 == 1)
    {
        total += (udp.data[length - 1] << 8);
    }
    uint16_t *header = reinterpret_cast<uint16_t *>(&udp.src_port);
    finish_checksum(&total, header, sizeof(udp_header) - sizeof(ip_header));
    udp.checksum = htons(static_cast<uint16_t>(total));
}

static void icmp_array_deleter_fn(icmp *p)
{
    ::operator delete[](static_cast<void *>(p));
}

std::unique_ptr<icmp, void (*)(icmp *)> icmp_ping_reply(icmp &msg, unsigned int buf_len)
{
    uint8_t *buf = new uint8_t[buf_len];
    icmp *typed_buf = reinterpret_cast<icmp *>(buf);
    std::unique_ptr<icmp, void (*)(icmp *)> reply(typed_buf, icmp_array_deleter_fn);
    uint8_t *dst_ip = reinterpret_cast<uint8_t *>(&msg.ip.dst_ip);
    uint8_t *src_ip = reinterpret_cast<uint8_t *>(&msg.ip.src_ip);
    setup_ip_header(reply->ip, IP_PROTOCOL_ICMP, std::vector<uint8_t>(dst_ip, dst_ip + 4),
                    std::vector<uint8_t>(src_ip, src_ip + 4), buf_len - sizeof(ip_header));
    memcpy(&reply->data, &msg.data, buf_len - sizeof(icmp));
    reply->type = ICMP_TYPE_ECHO_REPLY;
    reply->extended_header = msg.extended_header;
    reply->checksum = 0;
    reply->code = 0;
    unsigned int total = 0;
    if (buf_len % 2 == 1)
    {
        total += (msg.data[buf_len - 1] << 8);
    }
    finish_checksum(&total, reinterpret_cast<uint16_t *>(&typed_buf->type), buf_len - sizeof(ip_header));
    reply->checksum = htons(static_cast<uint16_t>(total));
    return reply;
}

bool verify_icmp_checksum(icmp *msg, int buf_len)
{
    unsigned int total = 0;
    if (buf_len % 2 == 1)
    {
        total += (msg->data[buf_len - 1] << 8);
    }
    finish_checksum(&total, reinterpret_cast<uint16_t *>(&msg->type), buf_len - sizeof(ip_header));
    return static_cast<uint16_t>(total) == 0;
}

bool verify_ip_checksum(ip_header *msg)
{
    unsigned int total = 0;
    uint16_t *header = reinterpret_cast<uint16_t *>(&msg->version_ihl);
    finish_checksum(&total, header, sizeof(ip_header) - sizeof(ethernet_header));
    return static_cast<uint16_t>(total) == 0;
}
