#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <iostream>
#include <cerrno>

#include "protocols.h"
#include "main.h"

#define TAP0 "tap0"

int tun_fd;

int tun_alloc(char *dev)
{
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    {
        throw std::runtime_error("Failed to open /dev/net/tun. This operation requires root privileges. Try running with sudo.");
    }
    memset(&ifr, 0, sizeof(ifr));
    // Use IFF_NO_PI so the kernel does not expect/require a 4-byte packet info header
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (dev != nullptr && *dev != '\0')
    {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
    {
        close(fd);
        throw std::runtime_error("Failed to set TUN/TAP interface. This operation requires root privileges. Try running with sudo.");
    }
    if (dev != nullptr && *dev != '\0')
    {
        std::strncpy(dev, ifr.ifr_name, IFNAMSIZ);
    }
    return fd;
}

int send_frame(int fd, const uint8_t *packet, size_t len)
{
    ssize_t n_written = write(fd, packet, len);
    if (n_written < 0)
    {
        int err = errno;
        throw std::runtime_error(std::string("Failed to write packet to TAP interface: ") + std::strerror(err));
    }
    return n_written;
}

int receive_frame(int fd, uint8_t *buffer, size_t len)
{
    ssize_t n_read = read(fd, buffer, len);
    if (n_read < 0)
    {
        throw std::runtime_error("Failed to read packet from TAP interface.");
    }
    return n_read;
}

std::vector<uint8_t> arp_lookup(std::vector<uint8_t> ip)
{
    auto arp_packet = create_arp_packet(
        PRETEND_MAC,   // Source MAC
        PRETEND_IP,    // Source IP
        MAC_BROADCAST, // Destination MAC (Broadcast)
        ip,            // Destination IP,
        ARP_REQUEST);
    int bytes_sent = send_frame(tun_fd, reinterpret_cast<const uint8_t *>(arp_packet.get()), sizeof(full_arp_packet));
    if (bytes_sent != sizeof(full_arp_packet))
    {
        throw std::runtime_error("Failed to send complete ARP request packet.");
    }
    uint8_t buffer[MAX_ETHERNET_FRAME_SIZE];
    int bytes_received = 0;
    full_arp_packet *arp_response = reinterpret_cast<full_arp_packet *>(buffer);
    arp_response->eth.type = 0;
    while (ntohs(arp_response->eth.type) != ETHERNET_TYPE_ARP || ntohs(arp_response->opcode) != ARP_REPLY || memcmp(arp_response->srcpr, ip.data(), 4) != 0)
    {
        std::memset(buffer, 0, sizeof(buffer));
        bytes_received = receive_frame(tun_fd, buffer, sizeof(buffer));
    }
    if (bytes_received < sizeof(full_arp_packet))
    {
        throw std::runtime_error("Received packet is smaller than an ARP packet.");
    }
    return get_mac_from_arp(arp_response);
}

bool arp_reply()
{
    uint8_t pretend_ip[] = PRETEND_IP;
    uint8_t buffer[MAX_ETHERNET_FRAME_SIZE];
    int bytes_received = 0;
    ethernet_header *eth = reinterpret_cast<ethernet_header *>(buffer);
    while (true)
    {
        std::memset(&buffer, 0, sizeof(buffer));
        bytes_received = receive_frame(tun_fd, buffer, sizeof(buffer));

        switch (ntohs(eth->type))
        {
        case ETHERNET_TYPE_ARP:
        {
            full_arp_packet *arp_response = reinterpret_cast<full_arp_packet *>(buffer);

            if (bytes_received < sizeof(full_arp_packet))
            {
                throw std::runtime_error("Received packet is smaller than an ARP packet.");
            }
            if (std::memcmp(arp_response->dstpr, pretend_ip, sizeof(pretend_ip)) == 0)
            {
                auto arp_packet = create_arp_packet(
                    PRETEND_MAC, // Source MAC
                    PRETEND_IP,  // Source IP
                    std::vector(arp_response->srchw, arp_response->srchw + 6),
                    std::vector(arp_response->srcpr, arp_response->srcpr + 4),
                    ARP_REPLY
                );
                int bytes_sent = send_frame(tun_fd, reinterpret_cast<const uint8_t *>(arp_packet.get()), sizeof(full_arp_packet));
                if (bytes_sent != sizeof(full_arp_packet))
                {
                    throw std::runtime_error("Failed to send complete ARP request packet.");
                }
            }
        }
        break;

        case ETHERNET_TYPE_IPV4:
        {
            ip_header *ip = reinterpret_cast<ip_header *>(buffer);
            if (std::memcmp(reinterpret_cast<uint8_t *>(&ip->dst_ip), &pretend_ip, sizeof(pretend_ip)) != 0)
            {
                continue;
            }
            if (!verify_ip_checksum(ip))
            {
                std::cout << "Bad IP checksum detected" << std::endl;
                continue;
            }
            if (ip->protocol == IP_PROTOCOL_ICMP)
            {
                icmp *req = reinterpret_cast<icmp *>(buffer);
                if (!verify_icmp_checksum(req, bytes_received))
                {
                    std::cout << "Bad ICMP checksum detected" << std::endl;
                    continue;
                }
                if (req->type == ICMP_TYPE_ECHO_REQUEST)
                {
                    auto reply = icmp_ping_reply(*req, bytes_received);
                    int bytes_sent = send_frame(tun_fd, reinterpret_cast<const uint8_t *>(reply.get()), bytes_received);
                }
            }
        }
        break;
        default:
            break;
        }
    }
}

int main()
{
    char name[IFNAMSIZ];
    std::memset(name, 0, IFNAMSIZ);
    std::strncpy(name, TAP0, strlen(TAP0));
    try
    {
        tun_fd = tun_alloc(name);
        if (system(("ip link set dev " + std::string(name) + " up").c_str()) != 0)
        {
            throw std::runtime_error("Failed to bring up the TAP interface. This operation requires root privileges. Try running with sudo.");
        }
        system(("ip addr add " + std::string(GATEWAY_IP_WITH_SUBNET_MASK) + " dev " + std::string(name)).c_str());
        std::cout << "TAP interface '" << name << "' created with file descriptor: " << tun_fd << std::endl;
        std::cout << "Hit enter to begin sending packets..." << std::endl;
        std::cin.get();
        udp_header *p1 = reinterpret_cast<udp_header *>(new uint8_t[sizeof(udp_header) + 2]);
        memcpy(p1->data, "s", 2);
        setup_udp_header(*p1, PRETEND_IP, GATEWAY_IP, 2, 1, 1);
        send_frame(tun_fd, reinterpret_cast<const uint8_t *>(p1), sizeof(udp_header) + 2);
        arp_reply();
        std::cout << "Exiting!" << std::endl;
        std::cin.get();
        close(tun_fd);
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}