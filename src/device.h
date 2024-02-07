#include <pcap.h>
#include <vector>
#include <string>
#include <netinet/in.h>
/**
* @file device.h
* @brief Library supporting network device management. */
extern std::vector <pcap_if_t*> mydevice;
extern std::vector <in_addr> IPaddr;
extern std::vector <char*> MACaddr;
extern std::vector <char*> IPname;
extern std::vector <std::string> mmacaddr;

int initDevice();
/**
* Add a device to the library for sending/receiving packets. *
* @param device Name of network device to send/receive packet on.
* @return A non-negative _device-ID_ on success, -1 on error. */
int addDevice(const char* device);
/**
* Find a device added by ‘addDevice‘. *
* @param device Name of the network device.
* @return A non-negative _device-ID_ on success, -1 if no such device
* was found. */
int findDevice(const char* device);
int setIPandMAC();



