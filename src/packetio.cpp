#include "device.h"
#include "packetio.h"
#include "ip.h"
#include <iostream>
#include <cstring>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
using namespace std;


int sendFrame(const void* buf, int len, int ethtype , const void* destmac , int id)
{
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    u_char packet[ETHER_MAX_LEN];
    if (id==-1)
    {
        cerr<<"Couldn't find the device"<<endl;
        return -1;
    }
    char* dev=mydevice[id]->name;
    handle = pcap_open_live(dev, 65535, 0, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Couldn't open device " << dev << ": " << errbuf <<endl;
        return -1;
    }
    
    ether_header etherHeader;
    etherHeader.ether_type = htons(ethtype);

    char* shost=(char*)mmacaddr[id].c_str();
    ether_addr* shost_addr=ether_aton(shost);
    memcpy(etherHeader.ether_shost,shost_addr,ETHER_ADDR_LEN);
    /*复制mac地址的时候要一个个复制！他只有一个buf会覆盖掉！*/
    const char* dhost=(const char*)destmac;
    ether_addr* dhost_addr=ether_aton(dhost);
    memcpy(etherHeader.ether_dhost, dhost_addr, ETHER_ADDR_LEN);

    
    memcpy(packet, &etherHeader, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), buf, len);
    /*
    cout<<endl<<"send frame"<<endl;
    cout<<"Protocol Type: "<<etherHeader.ether_type<<" ";
    printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",etherHeader.ether_shost[0],etherHeader.ether_shost[1],etherHeader.ether_shost[2],etherHeader.ether_shost[3],etherHeader.ether_shost[4],etherHeader.ether_shost[5]);
    printf("Dest MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",etherHeader.ether_dhost[0],etherHeader.ether_dhost[1],etherHeader.ether_dhost[2],etherHeader.ether_dhost[3],etherHeader.ether_dhost[4],etherHeader.ether_dhost[5]);
    */
    if (pcap_inject(handle, packet, len + sizeof(struct ether_header)) ==-1) {
        cerr << "Error sending packet: " << pcap_geterr(handle) << endl;
        pcap_close(handle);
        return -1;
    }
    pcap_close(handle);
    return 0;
}

int MyframeReceiveCallback(const void* buf,int len, int id)
{
    if (id==-1)
    {
        cout<<"Device doesn't exist"<<endl;
        return -1;
    }
    ether_header *etherHeader = (ether_header*)buf;
    /*
    cout<<endl<<"recevie frame"<<endl;
    cout<<"Protocol Type: "<<etherHeader->ether_type<<" ";
    printf("Source MAC : %02X-%02X-%02X-%02X-%02X-%02X==>",etherHeader->ether_shost[0],etherHeader->ether_shost[1],etherHeader->ether_shost[2],etherHeader->ether_shost[3],etherHeader->ether_shost[4],etherHeader->ether_shost[5]);
    printf("Dest MAC : %02X-%02X-%02X-%02X-%02X-%02X\n",etherHeader->ether_dhost[0],etherHeader->ether_dhost[1],etherHeader->ether_dhost[2],etherHeader->ether_dhost[3],etherHeader->ether_dhost[4],etherHeader->ether_dhost[5]);
    */
    char* shost=(char*)mmacaddr[id].c_str();
    char sshost[18];
    ether_addr* sshost_addr=ether_aton(shost);
    char* recv_shost=ether_ntoa(sshost_addr);
    memcpy(sshost,recv_shost,strlen(recv_shost));
    ether_addr* shost_addr=new ether_addr;
    memcpy(shost_addr,etherHeader->ether_shost,ETH_ALEN);
    recv_shost=ether_ntoa(shost_addr);
    //cout<<endl<<sshost<<endl<<recv_shost<<endl;
    if (strcmp(sshost,recv_shost)==0)
    {
        return 1;
    }
    

    u_char* buff=(u_char*)buf;
    if(ntohs(etherHeader->ether_type)==ETHERTYPE_ARP)
    {
        
        return arp_handler(buff+sizeof(struct ether_header),len-sizeof(struct ether_header),id);
    }
    else if (ntohs(etherHeader->ether_type)==ETHERTYPE_IP)
    {
        return IP_handler(buff+sizeof(struct ether_header),len-sizeof(struct ether_header),id);
    }
    /*
    u_char* data=(u_char*) buf;
     int i;  
        for(i=0; i<len; ++i)  {  
            printf(" %02x", data[i]);  
            if( (i + 1) % 16 == 0 )   
                printf("\n");  
        }  
        printf("\n\n");
        */
    return 1;

}


void pcap_handle(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
    const char* device=(const char*) user;
    MyframeReceiveCallback(pkt_data,header->len,findDevice(device));
}

int FrameReceiveCallback(const char* device) 
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* phandle;


    phandle = pcap_open_live(device, 65535, 0, 1000, errbuf); 
    if (phandle == nullptr) 
    {
        cerr << "Couldn't open device: " << errbuf << endl;
        return -1;
    }
    u_char * devname=(u_char*) device;
    pcap_loop(phandle,-1,pcap_handle,devname); 

    
    return 0;
}


int get_myMAC(int id, char* res)
{
    const char* interfaceName =mydevice[id]->name; // 替换为您要查询的接口名称
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, interfaceName, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("ioctl");
        close(sockfd);
        return -1;
    }

    unsigned char* macAddress = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    close(sockfd);
    sprintf((char *)res,(const char *)"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    
    return 1;
}