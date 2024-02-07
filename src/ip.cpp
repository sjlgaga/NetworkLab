#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "routing.h"
#include "socket.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <mutex>
using namespace std;

vector<route_table> rt_table;
vector<ARP_table> arp_table;
mutex arp_lock;

int sendIPPacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len)
{
    u_char packet[IP_MAXPACKET];

    ip ipHeader;
    ipHeader.ip_v=IPVERSION;
    ipHeader.ip_hl=5;
    ipHeader.ip_tos=0;
    ipHeader.ip_len=htons(sizeof(ip)+len);
    ipHeader.ip_id=htons(0);
    ipHeader.ip_ttl = 64;
    ipHeader.ip_p=proto;         
    ipHeader.ip_src = src;
    ipHeader.ip_dst = dest;
    memcpy(packet, &ipHeader, sizeof(struct ip));
    memcpy(packet+sizeof(struct ip),buf,len);

    if (dest.s_addr==0xFFFFFFFF)
    {
        const char* destmac="ff:ff:ff:ff:ff:ff";
        int devnum=mydevice.size();
        for (int i=0;i<devnum;i++)
        {
            if (sendFrame(packet,len+sizeof(struct ip),ETHERTYPE_IP,destmac,i)==-1)
            {
                cerr<<"send IP packet error"<<endl;
                return -1;
            }
        }
        return 1;
    }
    
    int best_match=-1;
    uint32_t myaddr=dest.s_addr;
    char *destmac=new char[18];
    char* init="00:00:00:00:00:00";
    memcpy(destmac,init,strlen(init));
    int id=-1;
    
    for (auto entry:rt_table)
    {
        
        int match=0;
        uint32_t cmpaddr=entry.dest.s_addr;
        uint32_t mask=entry.mask.s_addr;
        int i=31;
        while (((mask>>i)&0x1)==1)
        {
            if (i<0)
                break;
            if (((myaddr>>i)&0x1)!=((cmpaddr>>i)&0x1))
            {
                break;
            }
            match++;
            i--;
        }
        
        if (match>best_match)
        {
            best_match=match;
            destmac=entry.nextHopMAC;
            id=entry.id;
        }
        
    }

    if (strcmp(destmac,init)!=0)
    {
        if (sendFrame(packet,len+sizeof(struct ip),ETHERTYPE_IP,(const char*)destmac,id)==-1)
        {
            cerr<<"send IP packet error"<<endl;
            return -1;
        }
    }
    else
    {
        cout<<"route table may be resetting"<<endl;
        setRouteTable();
    }
        
    return 1;
    
}

int IP_handler(const void* buf, int len,int id)
{
    struct ip* ipHeader = (struct ip*)buf; 
    /*
    cout << "Source IP: " << ipHeader->ip_src.s_addr << endl;
    cout << "Destination IP: " << ipHeader->ip_dst.s_addr << endl;
    cout<<endl;
    */
    
    uint8_t proto=(ipHeader->ip_p);
    if ((int)proto==2)
        recv_route((ipHeader->ip_src), buf+sizeof(struct ip),len-sizeof(struct ip), id);

    if (ipHeader->ip_dst.s_addr==0xFFFFFFFF)
    {
        return 1;
    }
    int devnum=mydevice.size();
    
    in_addr myip;
    for (int i=0;i<devnum;i++)
    {
        myip.s_addr=IPaddr[i].s_addr;
        if (myip.s_addr==ipHeader->ip_dst.s_addr)
        {
            cout<<"Receive specific ip packet!"<<endl;
            if (proto==IPPROTO_TCP)
            {
                TCPhandler(ipHeader->ip_src,ipHeader->ip_dst,buf+sizeof(struct ip),len-sizeof(struct ip));
            }
            return 1;
        }
    }

    if (sendIPPacket(ipHeader->ip_src,ipHeader->ip_dst,ipHeader->ip_p,buf+sizeof(struct ip),len-sizeof(struct ip))==-1)
    {
        cerr<<"transfer IP packet error"<<endl;
        return -1;
    }
    return 1;
}

int get_myIP(struct in_addr* src,int id)
{
    pcap_if_t* alldevs;

    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs,errbuf)==-1)
    {
        cerr<<"Error in pcap_findalldevs:"<<errbuf<<endl;
        return -1;
    }
    pcap_if_t* curdev;
    for (curdev=alldevs;curdev!=NULL;curdev=curdev->next)
    {
        if (strcmp(curdev->name,mydevice[id]->name)==0)
        {
            for(pcap_addr_t *a=curdev->addresses; a!=NULL; a=a->next) 
            {
                if(a->addr->sa_family == AF_INET)
                {
                    memcpy(src,&(((struct sockaddr_in*)a->addr)->sin_addr),sizeof(struct in_addr));
                    return 1;
                }
                    
                
            }
        }
    }
    /*
    pcap_if_t* d=mydevice[id];
    for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) 
    {
            if(a->addr->sa_family == AF_INET)
                memcpy(src,&(((struct sockaddr_in*)a->addr)->sin_addr),sizeof(struct in_addr));
    }
    */
    return -1;
}

int sendARPRequest(const struct in_addr dest,int id)
{

    struct  ether_arp  *arp=new ether_arp;
    char* src_mac=(char*)mmacaddr[id].c_str();

    const char* dst_mac= "ff:ff:ff:ff:ff:ff";
    ether_addr* dhost_addr=ether_aton(dst_mac);
    memcpy(arp->arp_tha,dhost_addr,ETH_ALEN);
    ether_addr* shost_addr=ether_aton(src_mac);
    memcpy(arp->arp_sha,shost_addr,ETH_ALEN);
    



    struct in_addr  srcIP;
    srcIP.s_addr=IPaddr[id].s_addr;

    memcpy(arp->arp_spa,&srcIP,4);
    memcpy(arp->arp_tpa,&dest,4);
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    return sendFrame(arp,sizeof(struct ether_arp),ETHERTYPE_ARP,dst_mac,id);
}

int sendARPReply(const struct in_addr src, const struct in_addr dest,const char* srcmac,const char* destmac,int id)
{
    struct  ether_arp  *arp=new ether_arp;
    ether_addr* dhost_addr=ether_aton(destmac);
    memcpy(arp->arp_tha,dhost_addr,ETHER_ADDR_LEN);
    ether_addr* shost_addr=ether_aton(srcmac);
    memcpy(arp->arp_sha,shost_addr,ETHER_ADDR_LEN);
    
    memcpy(arp->arp_spa,&src,4);
    memcpy(arp->arp_tpa,&dest,4);
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = ETH_ALEN;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    ether_addr* sendermac_host=(ether_addr*)arp->arp_sha;
    ether_addr* targetmac_host=(ether_addr*)arp->arp_tha;
    
    /*
    cout<<endl<<"send arp reply from device: "<<mydevice[id]->name<<endl;
    cout<<"senderip:"<<src.s_addr<<endl;
    cout<<"targetip: "<<dest.s_addr<<endl;
    const char* sendermac=ether_ntoa(sendermac_host);
    cout<<"sendermac: "<<sendermac<<endl;
    const char* targetmac=ether_ntoa(targetmac_host);
    cout<<"targetmac: "<<targetmac<<endl;
    cout<<endl;
    */
    return sendFrame(arp,sizeof(struct ether_arp),ETHERTYPE_ARP,destmac,id);
}

int recvARPRequest(const void* buf,int len, int id)
{
    arp_lock.lock();
    struct  ether_arp  *arp=(struct ether_arp*)buf;
    in_addr myip,targetip,senderip;
    memcpy(&senderip,arp->arp_spa,4);
    memcpy(&targetip,arp->arp_tpa,4);
    myip.s_addr=IPaddr[id].s_addr;
    if (myip.s_addr==senderip.s_addr)
    {
        arp_lock.unlock();
        return 1;
    }
    ether_addr* sendermac_host=(ether_addr*)arp->arp_sha;
    const char* sendermac=ether_ntoa(sendermac_host);
    if (myip.s_addr==targetip.s_addr)
    {
        char* mymac=(char*)mmacaddr[id].c_str();
        sendARPReply(myip,senderip,mymac,sendermac,id);
    }
    arp_lock.unlock();
    return 1;
}

int recvARPReply(const void* buf,int len,int id)
{
    struct  ether_arp  *arp=(struct ether_arp*)buf;
    ether_addr* sendermac_host=(ether_addr*)arp->arp_sha;
    ether_addr* targetmac_host=(ether_addr*)arp->arp_tha;
   
   
    in_addr senderip,myip,targetip;
    memcpy(&senderip,arp->arp_spa,4);
    memcpy(&targetip,arp->arp_tpa,4);
    myip.s_addr=IPaddr[id].s_addr;
    if (myip.s_addr==senderip.s_addr)
    {
        return 1;
    }
     arp_lock.lock();
    const char* sendermac=ether_ntoa(sendermac_host);
     /*
    cout<<endl;
    cout<<"receive arp reply from device: "<<mydevice[id]->name<<endl;
    cout<<"senderip:"<<senderip.s_addr<<endl;
    cout<<"targetip: "<<targetip.s_addr<<endl;
    cout<<"sendermac: "<<sendermac<<endl;
     const char* targetmac=ether_ntoa(targetmac_host);
    cout<<"targetmac: "<<targetmac<<endl;
     cout<<"##################before################"<<endl;
     printARPtable();
     */
    sendermac=ether_ntoa(sendermac_host);
    ARP_table arp_entry;
    arp_entry.ipaddr=senderip;
    memcpy(arp_entry.macaddr,sendermac,strlen(sendermac));
    arp_entry.macaddr[strlen(sendermac)]='\0';
    bool flag=false;
    
    
    for (auto i:arp_table)
    {
        if (i.ipaddr.s_addr==senderip.s_addr)
        {
            flag=true;
            break;
        }
    }
     
     
    if (flag==false)
        arp_table.push_back(arp_entry);
    /*
     cout<<"##################after################"<<endl;
    printARPtable();
    cout<<endl;
    */
    arp_lock.unlock();
    
    return 1;
}

int arp_handler(const void* buf,int len, int id)
{
    struct  ether_arp  *arp=(struct ether_arp*)buf;
    unsigned short int type=ntohs(arp->ea_hdr.ar_op);
    if (type==ARPOP_REQUEST)
    {
        if (recvARPRequest(buf,len,id)==-1)
        {
            cerr<<"receive arp request packet error"<<endl;
            return -1;
        }
    }
    else if (type==ARPOP_REPLY)
    {
        if (recvARPReply(buf,len,id)==-1)
        {
            cerr<<"receive arp reply packet error"<<endl;
            return -1;
        }
    }
    return -1;
}