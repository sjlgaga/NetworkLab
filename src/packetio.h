/**
* @file packetio.h
* @brief Library supporting sending/receiving Ethernet II frames. */
#include <netinet/ether.h>
/**
* @brief Encapsulate some data into an Ethernet II frame and send it. *
* @param buf Pointer to the payload.
* @param len Length of the payload.
* @param ethtype EtherType field value of this frame.
* @param destmac MAC address of the destination.
* @param id ID of the device(returned by ‘addDevice‘) to send on.
* @return 0 on success, -1 on error.
* @see addDevice */
int sendFrame(const void* buf, int len, int ethtype , const void* destmac , int id);
/**
* @brief *
* @param
* @param
* @param *
* @return 0 on success, -1 on error.
* @see addDevice */
typedef int (*frameReceiveCallback)(const void*, int, int);
/*
Process a frame upon receiving it.
buf Pointer to the frame.
len Length of the frame.
id ID of the device (returned by ‘addDevice‘) receiving current frame.
*/
/**
* @brief *
*
* @param
* @return 0 on success, -1 on error.
* @see frameReceiveCallback */
/*
Register a callback function to be called each time an Ethernet II frame was received.
callback the callback function.
*/
int FrameReceiveCallback(const char* device);

int get_myMAC(int id, char* res);
