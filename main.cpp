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
#include <map>
#include <thread>
#include <chrono>

#include "protocols.h"
#include "main.h"

#define TAP0 "tap0"

int tun_fd;

std::map<std::vector<uint8_t>, std::vector<uint8_t>> arp_cache;
std::map<std::string, std::vector<uint8_t>> dns_cache;

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
    // Check if IP is on the same network as PRETEND_IP
    if (ip.size() != 4)
    {
        throw std::runtime_error("IP of invalid length");
    }
    uint8_t network_addr1[] = PRETEND_IP;
    std::vector<uint8_t> copy_ip(ip);
    uint8_t *network_addr2 = copy_ip.data();
    uint8_t subnet_mask[] = SUBNET_MASK;
    for (int i = 0; i < 4; i++)
    {
        network_addr1[i] &= subnet_mask[i];
        network_addr2[i] &= subnet_mask[i];
    }
    if (memcmp(network_addr2, &network_addr1, 4) != 0)
    {
        copy_ip = GATEWAY_IP;
    }
    else
    {
        copy_ip = ip;
    }
    auto mac_ip = arp_cache.find(copy_ip);
    if (mac_ip != arp_cache.end())
    {
        return arp_cache[copy_ip];
    }
    auto arp_packet = create_arp_packet(
        PRETEND_MAC,   // Source MAC
        PRETEND_IP,    // Source IP
        MAC_BROADCAST, // Destination MAC (Broadcast)
        copy_ip,       // Destination IP,
        ARP_REQUEST);
    int bytes_sent = send_frame(tun_fd, reinterpret_cast<const uint8_t *>(arp_packet.get()), sizeof(full_arp_packet));
    if (bytes_sent != sizeof(full_arp_packet))
    {
        throw std::runtime_error("Failed to send complete ARP request packet.");
    }
    while (arp_cache.find(copy_ip) == arp_cache.end())
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return arp_cache[copy_ip];
}

void mainloop()
{
    uint8_t pretend_ip[] = PRETEND_IP;
    uint8_t pretend_mac[] = PRETEND_MAC;
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
                if (ntohs(arp_response->opcode) == ARP_REQUEST)
                {
                    auto arp_packet = create_arp_packet(
                        PRETEND_MAC, // Source MAC
                        PRETEND_IP,  // Source IP
                        std::vector(arp_response->srchw, arp_response->srchw + 6),
                        std::vector(arp_response->srcpr, arp_response->srcpr + 4),
                        ARP_REPLY);
                    int bytes_sent = send_frame(tun_fd, reinterpret_cast<const uint8_t *>(arp_packet.get()), sizeof(full_arp_packet));
                    if (bytes_sent != sizeof(full_arp_packet))
                    {
                        throw std::runtime_error("Failed to send complete ARP request packet.");
                    }
                }
                if (ntohs(arp_response->opcode) == ARP_REPLY)
                {
                    if (bytes_received < sizeof(full_arp_packet))
                    {
                        throw std::runtime_error("Received packet is smaller than an ARP packet.");
                    }
                    auto mac = get_mac_from_arp(arp_response);
                    arp_cache[std::vector(arp_response->srcpr, arp_response->srcpr + 4)] = mac;
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
            switch (ip->protocol)
            {
            case IP_PROTOCOL_ICMP:
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
            break;

            case IP_PROTOCOL_UDP:
            {
                std::cout << "Parsing DNS" << std::endl;
                udp_header *udp = reinterpret_cast<udp_header *>(buffer);
                if (!verify_udp_checksum(udp, bytes_received))
                {
                    std::cout << "Bad UDP checksum detected" << std::endl;
                    continue;
                }
                {
                    // Assuming this is DNS response - how can I check for this?
                    dns_header *dns = reinterpret_cast<dns_header *>(buffer);
                    if (dns->flags & 0xF != 0)
                    {
                        std::cout << "DNS ERROR DETECTED" << std::endl;
                        continue;
                    }
                    std::string name;
                    std::vector<uint8_t> ip_rec;
                    std::tie(name, ip_rec) = parse_dns_response(dns, bytes_received);
                    dns_cache[name] = ip_rec;
                }
            }
            break;

            default:
                break;
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
        std::cout << "Hit enter to begin..." << std::endl;
        std::cin.get();
        std::thread in(mainloop);
        std::string domain = "google.com";
        size_t packet_size;
        auto p1 = dns_make_query(domain, 2, PRETEND_IP, DNS_IP, &packet_size);
        send_frame(tun_fd, p1.get(), packet_size);
        while (dns_cache.find(domain) == dns_cache.end())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        std::vector<uint8_t> ip = dns_cache[domain];
        std::cout << "Successfully found ";
        std::cout << domain << " at: {";
        for (uint8_t data : ip)
        {
            std::cout << " " << data << ",";
        }
        std::cout << "}" << std::endl;
        in.join();
        close(tun_fd);
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}