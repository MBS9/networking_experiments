#include <vector>
#include <cstdint>

#define SUBNET_MASK {255, 255, 255, 0}

// The below refer to the ip and mac address assigned to the current computer
// Since the tap interface isn't connected to any network, these can be arbitrary
#define GATEWAY_IP {10, 0, 0, 1}
#define GATEWAY_IP_WITH_SUBNET_MASK "10.0.0.1/24"

#define DNS_IP {1, 1, 1, 1}

// The below is a random MAC address that doesn't belong to the current computer
// It is a pretend address of another device on the same network
#define PRETEND_MAC {0x01, 0x57, 0x47, 0x85, 0x1f, 0xc6}
#define PRETEND_IP {10, 0, 0, 2}

std::vector<uint8_t> arp_lookup(std::vector<uint8_t> ip);
