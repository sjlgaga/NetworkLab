/**
* @file ip.h
* @brief Library supporting sending/receiving IP packets encapsulated
in an Ethernet II frame. */
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <vector>
#include <string>

struct route_table
{
    struct in_addr dest,mask;
    char nextHopMAC[18];
    int id;
};

struct ARP_table
{
    struct in_addr ipaddr;
    char macaddr[18];
};

extern std::vector<ARP_table> arp_table;
extern std::vector<route_table> rt_table;
/**
* @brief Send an IP packet to specified host. *
* @param src Source IP address.
* @param dest Destination IP address.
* @param proto Value of ‘protocol‘ field in IP header.
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success, -1 on error. */
int sendIPPacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len);

/**
* @brief Process an IP packet upon receiving it. *
* @param buf Pointer to the packet.
* @param len Length of the packet.
* @return 0 on success, -1 on error.
* @see addDevice */
typedef int (*IPPacketReceiveCallback)(const void* buf, int len);

/**
* @brief Register a callback function to be called each time an IP
packet was received. *
* @param callback The callback function.
* @return 0 on success, -1 on error.
* @see IPPacketReceiveCallback */
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);

/**
* @brief Manully add an item to routing table. Useful when talking
with real Linux machines. *
* @param dest The destination IP prefix.
* @param mask The subnet mask of the destination IP prefix.
* @param nextHopMAC MAC address of the next hop.
* @param device Name of device to send packets on.
* @return 0 on success, -1 on error */
int setRoutingTable(const struct in_addr dest, const struct in_addr mask ,
const void* nextHopMAC , const char *device);

int get_myIP(struct in_addr* src,int id);

int IP_handler(const void* buf, int len,int id);

int sendARPRequest(const struct in_addr dest,int id);

int sendARPReply(const struct in_addr src, const struct in_addr dest,const char* srcmac,const char* destmac,int id);

int recvARPRequest(const void* buf,int len, int id);

int recvARPReply(const void* buf,int len,int id);

int arp_handler(const void* buf,int len, int id);

