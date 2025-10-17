#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <iostream>
#include <cerrno>

#include "protocols.h"

// The below refer to the ip and mac address assigned to the current computer
// Since the tap interface isn't connected to any network, these can be arbitrary
#define OWN_IP {10, 0, 0, 1}
#define OWN_IP_WITH_SUBNET_MASK "10.0.0.1/24"

// The below is a random MAC address that doesn't belong to the current computer
// It is a pretend address of another device on the same network
#define PRETEND_MAC {0x01, 0x57, 0x47, 0x85, 0x1f, 0xc6}
#define PRETEND_IP {10, 0, 0, 2}

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

int main()
{
    char name[IFNAMSIZ];
    std::memset(name, 0, IFNAMSIZ);
    std::strncpy(name, "tap0", strlen("tap0"));
    try
    {
        int tun_fd = tun_alloc(name);
        if (system(("ip link set dev " + std::string(name) + " up").c_str()) != 0)
        {
            throw std::runtime_error("Failed to bring up the TAP interface. This operation requires root privileges. Try running with sudo.");
        }
        system(("ip addr add " + std::string(OWN_IP_WITH_SUBNET_MASK) + " dev " + std::string(name)).c_str());
        std::cout << "TAP interface '" << name << "' created with file descriptor: " << tun_fd << std::endl;
        std::cout << "Hit enter to begin sending ARP packets..." << std::endl;
        std::cin.get();
        const full_arp_packet *arp_packet = create_arp_packet(
            PRETEND_MAC,   // Source MAC
            PRETEND_IP,    // Source IP
            MAC_BROADCAST, // Destination MAC (Broadcast)
            OWN_IP         // Destination IP
        );
        int bytes_sent = send_frame(tun_fd, reinterpret_cast<const uint8_t *>(arp_packet), sizeof(full_arp_packet));
        delete arp_packet;
        std::cout << "Sent " << bytes_sent << " bytes" << std::endl;
        std::cin.get();
        close(tun_fd);
    }
    catch (const std::runtime_error &e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "Exiting." << std::endl;

    return 0;
}