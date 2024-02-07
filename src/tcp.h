#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <mutex>

struct Connect
{
    sockaddr_in myaddr;
    sockaddr_in aiteaddr;
    int state;
    /*
    0:default
    1:syn_sent
    2:syn_recvd
    3:established
    4:fin wait1
    5:passively waiting fin
    6:fin wait2
    7:last ack
    8:closed
    */
    u_int32_t curseq;
    u_int32_t curack;
    u_int32_t nextseq;
    u_int8_t flag;
    u_char sendbuf[IP_MAXPACKET-24];
    int sendbuflen;
    u_char recvbuf[10*(IP_MAXPACKET-24)];
    u_char* writept;
    u_char* readpt;
    std::mutex cotlock;

};

int sendTCPSegment(int fd);
int listening_handler(int socknum,in_addr srcip,in_addr destip,const void* buf, int len);
int start_handler(int socknum,const void* buf, int len);
int established_hanler(int socknum,const void* buf, int len);
int end_handler(int socknum,const void* buf, int len);
int TCPhandler(in_addr srcip,in_addr destip,const void* buf, int len);
int wait_to_close(int socknum);