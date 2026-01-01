#include <arpa/inet.h>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <iostream>
#include <memory>
#include <tuple>
#include "protocols.h"
#include "main.h"

void setup_ethernet_header(ethernet_header &eth, const std::vector<uint8_t> &dst, const std::vector<uint8_t> &src, uint16_t type)
{
    std::memcpy(eth.dst, dst.data(), HARDWARE_ADDR_LEN);
    std::memcpy(eth.src, src.data(), HARDWARE_ADDR_LEN);
    eth.type = htons(type);
}

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

uint16_t udp_checksum(udp_header *udp, size_t length)
{
    size_t data_len = length - sizeof(udp_header);
    uint8_t *src_ip = reinterpret_cast<uint8_t *>(&udp->ip.src_ip);
    uint8_t *dst_ip = reinterpret_cast<uint8_t *>(&udp->ip.dst_ip);
    uint8_t *data = reinterpret_cast<uint8_t *>(udp) + sizeof(udp_header);
    unsigned int total = 0;
    total += (src_ip[0] << 8) | src_ip[1];
    total += (src_ip[2] << 8) | src_ip[3];
    total += (dst_ip[0] << 8) | dst_ip[1];
    total += (dst_ip[2] << 8) | dst_ip[3];
    total += IP_PROTOCOL_UDP;
    total += length - sizeof(ip_header);
    int i;
    for (i = 0; i < data_len - 1; i += 2)
    {
        total += (data[i] << 8) | data[i + 1];
    }
    if (data_len % 2 == 1)
    {
        total += (data[data_len - 1] << 8);
    }
    uint16_t *header = reinterpret_cast<uint16_t *>(&udp->src_port);
    finish_checksum(&total, header, sizeof(udp_header) - sizeof(ip_header));
    return htons(static_cast<uint16_t>(total));
}

void setup_udp_header(udp_header &udp, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, uint16_t length,
                      uint16_t dst_port, uint16_t src_port)
{
    uint16_t udp_len = length - sizeof(ip_header);
    setup_ip_header(udp.ip, IP_PROTOCOL_UDP, src_ip, dst_ip, udp_len);
    udp.dst_port = htons(dst_port);
    udp.src_port = htons(src_port);
    udp.length = htons(udp_len);
    udp.checksum = 0;
    udp.checksum = udp_checksum(&udp, length);
}

std::unique_ptr<uint8_t[]> icmp_ping_reply(icmp &msg, unsigned int buf_len)
{
    std::unique_ptr<uint8_t[]> buf(new uint8_t[buf_len]);

    icmp *reply = reinterpret_cast<icmp *>(buf.get());

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
    finish_checksum(&total, reinterpret_cast<uint16_t *>(&reply->type), buf_len - sizeof(ip_header));
    reply->checksum = htons(static_cast<uint16_t>(total));
    return buf;
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

bool verify_udp_checksum(udp_header *udp, size_t buf_len)
{
    return udp_checksum(udp, buf_len) == 0;
}

std::unique_ptr<uint8_t[]> dns_make_query(std::string domain, uint16_t query_id, std::vector<uint8_t> src_ip, std::vector<uint8_t> dst_ip, size_t *packet_size)
{
    std::vector<std::string> labels;
    size_t start = 0;
    size_t next_dot = 0;
    while (next_dot != std::string::npos)
    {
        next_dot = domain.find('.', start);
        labels.push_back(domain.substr(start, next_dot - start));
        start = next_dot + 1;
    }
    size_t length = sizeof(dns_header) + domain.length() + 2 + 4;
    *packet_size = length;
    std::unique_ptr<uint8_t[]> buf(new uint8_t[length]);
    dns_header *typed_buf = reinterpret_cast<dns_header *>(buf.get());
    uint8_t *qd = buf.get() + sizeof(dns_header);
    typed_buf->id = htons(query_id);
    typed_buf->flags = htons(0x0100);
    typed_buf->qdcount = htons(1);
    size_t label_start = 0;
    for (size_t idx = 0; idx < labels.size(); idx++)
    {
        std::string label = labels[idx];
        qd[label_start] = static_cast<uint8_t>(label.length());
        memcpy(qd + label_start + 1, labels[idx].data(), label.length());
        label_start += label.length() + 1;
    }
    // Set QTYPE = A and QCLASS = IN
    qd[label_start] = 0;
    qd[label_start + 1] = 0;
    qd[label_start + 2] = 1;
    qd[label_start + 3] = 0;
    qd[label_start + 4] = 1;
    setup_udp_header(typed_buf->udp, src_ip, dst_ip, length, 53, 100);
    return buf;
}

std::string parse_label(uint8_t **cursor, uint8_t *dns_begin)
{
    // This is vulernable to buffer overflow...but for now I don't care
    std::string domain = "";
    size_t offset_candidate = static_cast<size_t>(ntohs(*reinterpret_cast<uint16_t *>(*cursor)));
    if ((offset_candidate & 0xc000) == 0xc000)
    {
        // We are using compression
        size_t offset = offset_candidate & 0x3FFF;
        uint8_t *new_cursor = dns_begin + offset;
        *cursor += 2;
        domain = parse_label(&new_cursor, dns_begin);
        return domain;
    }
    while (true)
    {
        size_t label_len = **cursor;
        if (label_len == 0)
            break;
        *cursor += 1;
        domain += std::string(*cursor, *cursor + label_len);
        domain += ".";
        *cursor += label_len;
    }
    domain.pop_back();
    // Move to first byte in next field
    *cursor += 1;
    return domain;
}

std::tuple<std::string, std::vector<uint8_t>> parse_dns_response(dns_header *buf, size_t buf_len)
{
    uint8_t *cursor = reinterpret_cast<uint8_t *>(buf) + sizeof(dns_header);
    uint8_t *dns_begin = reinterpret_cast<uint8_t *>(buf) + sizeof(udp_header);
    size_t qdcount = ntohs(buf->qdcount);
    for (int i = 0; i < qdcount; i++)
    {
        parse_label(&cursor, dns_begin);
        cursor += 4;
    }
    size_t ancount = ntohs(buf->ancount);
    for (int i = 0; i < ancount; i++)
    {
        auto domain = parse_label(&cursor, dns_begin);
        if (*reinterpret_cast<uint16_t *>(cursor) != htons(1))
        {
            // Oh no... This is not an A record
            // Skip
            continue;
        }
        uint8_t *rdlen = cursor + 8; // Skip over class, ttl assume we don't need them
        uint16_t ip_len = ntohs(*reinterpret_cast<uint16_t *>(rdlen));
        uint8_t *ip_data = rdlen + 2;
        if (ip_len != 4)
        {
            // Weird...
            std::cout << "IPv4 addr doesn't have 4 bytes" << std::endl;
            continue;
        }
        std::vector<uint8_t> ip(ip_data, ip_data + ip_len);
        return std::make_tuple(domain, ip);
    }
    // Failure
    std::cout << "Unable to parse DNS packet" << std::endl;
    return std::make_tuple("", std::vector<uint8_t>({0, 0, 0, 0}));
}
