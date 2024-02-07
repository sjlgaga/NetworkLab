#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "routing.h"
#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>
#include <mutex>
#include <set>
using namespace std;

//dv:distance vecotr
//fd:forwarding table
vector<dv_node> dv;
vector<FD_table> fd_table;
set<in_addr_t> hopadr;
mutex dv_lock,fd_lock;

int sendRoutePacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len,int id)
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

    const char* destmac="ff:ff:ff:ff:ff:ff";
    if (sendFrame(packet,len+sizeof(struct ip),ETHERTYPE_IP,destmac,id)==-1)
    {
        cerr<<"send route config packet error"<<endl;
        return -1;
    }
    return 1;
    
}

int send_dv()
{
    dv_lock.lock();
    int devnum=mydevice.size();
    int dvnum=dv.size();

    in_addr dst;
    const char* dststring="255.255.255.255";
    inet_pton(AF_INET,dststring,&dst);
    u_char payload[IP_MAXPACKET-5];

    for (int i=0;i<dvnum;i++)
    {
        memcpy(payload+i*sizeof(struct dv_node),&(dv[i]),sizeof(struct dv_node));       
    }
    for (int i=0;i<devnum;i++)
    {
        in_addr myip;
        myip.s_addr=IPaddr[i].s_addr;

        sendRoutePacket(myip,dst,ROUTESET,&payload,dvnum*sizeof(struct dv_node),i);
    }
    dv_lock.unlock();
    return 1;
}

int init_dv()
{
    dv.clear();
    fd_table.clear();
    int devnum=mydevice.size();
    dv_lock.lock();
    for (int i=0;i<devnum;i++)
    {
        in_addr myip;
        myip.s_addr=IPaddr[i].s_addr;
        dv_node tempnode;
        tempnode.dst=myip;
        tempnode.hopnum=0;
        dv.push_back(tempnode);
    }
    dv_lock.unlock();

    send_dv();
    return 1;
   
}

int recv_route(const in_addr src,const void* buf,int len, int id)
{
    dv_lock.lock();


    int num=len/sizeof(struct dv_node);
    struct dv_node* cur_node=new dv_node;
    bool renew=false;
    const char* buff=(const char*)buf;
    for (int i=0;i<num;i++)
    {
        cur_node=(dv_node*)(buff+i*sizeof(struct dv_node));
        bool has=false;

        for (auto &v:dv)
        {
            if (v.dst.s_addr==cur_node->dst.s_addr)
            {
                has=true;
                if (v.hopnum>cur_node->hopnum+1)
                {
                    renew=true;
                    v.hopnum=cur_node->hopnum+1;
                    fd_lock.lock();
                    for (auto &u:fd_table)
                    {
                        if (u.dst.s_addr==v.dst.s_addr)
                        {
                            u.nexthop.s_addr=src.s_addr;
                            u.id=id;
                        }
                    }
                    fd_lock.unlock();
                }
            }
        }

        if (has==false)
        {
            renew=true;
            dv_node new_node;
            new_node.dst.s_addr=cur_node->dst.s_addr;
            new_node.dst_mask=cur_node->dst_mask;
            new_node.hopnum=cur_node->hopnum+1;
            dv.push_back(new_node);

            fd_lock.lock();
            FD_table new_entry;
            new_entry.dst.s_addr=cur_node->dst.s_addr;
            new_entry.nexthop.s_addr=src.s_addr;
            if (new_entry.dst.s_addr==new_entry.nexthop.s_addr)
            {
                new_entry.dst_mask.s_addr=0xffffffff;
            }
            else
            {
                new_entry.dst_mask.s_addr=0x00ffffff;
            }
            new_entry.id=id;
            fd_table.push_back(new_entry);
            fd_lock.unlock();
        }
    }
    dv_lock.unlock();
    if (renew==true)
        send_dv();
    return 1;
}

int setRouteTable()
{
    for (auto node:fd_table)
    {
        if (hopadr.find(node.nexthop.s_addr)==hopadr.end())
        {
            sendARPRequest(node.nexthop,node.id);
            hopadr.insert(node.nexthop.s_addr);
        }
        
    }
    
    this_thread::sleep_for(chrono::seconds(3));
    for (auto i:fd_table)
    {
        for (auto j: arp_table)
        {
            if(i.nexthop.s_addr==j.ipaddr.s_addr)
            {
                route_table entry;
                entry.dest=i.dst;
                entry.mask=i.dst_mask;
                memcpy(entry.nextHopMAC,j.macaddr,strlen(j.macaddr));
                entry.nextHopMAC[strlen(j.macaddr)]='\0';
                entry.id=i.id;
                rt_table.push_back(entry);
                break;
            }
        }
        
    }
    
    return 1;
}

void printFDtable()
{
    cout<<"###############Forwarding Table##############"<<endl;
    for (auto fd:fd_table)
    {
        cout<<"dest IP:"<<fd.dst.s_addr<<endl;
        cout<<"netmask:"<<fd.dst_mask.s_addr<<endl;
        cout<<"nexthop IP:"<<fd.nexthop.s_addr<<endl;
        cout<<"device: "<<mydevice[fd.id]->name<<endl;
        cout<<endl;
    }
    cout<<"###############Forwarding Table##############"<<endl;
}

void printDV()
{
    cout<<"###############DV##############"<<endl;
    for (auto v:dv)
    {
        cout<<"dest IP:"<<v.dst.s_addr<<endl;
        cout<<"dest hopnum:"<<v.hopnum<<endl;
        cout<<endl;
    }
    cout<<"###############################"<<endl;
    cout<<endl;
}

void printRTtable()
{
    cout<<"###############RT##############"<<endl;
    for (auto v:rt_table)
    {
        cout<<"dest IP:"<<v.dest.s_addr<<endl;
        cout<<"mask: "<<v.mask.s_addr<<endl;
        cout<<"dest MAC:"<<v.nextHopMAC<<endl;
        cout<<"device: "<<mydevice[v.id]->name<<endl;
        cout<<endl;
    }
    cout<<"###############################"<<endl;
    cout<<endl;
}
void printARPtable()
{
    cout<<"###############ARP##############"<<endl;
    for (auto v:arp_table)
    {
        cout<<"dest IP:"<<v.ipaddr.s_addr<<endl;
        cout<<"dest MAC:"<<v.macaddr<<endl;
        cout<<endl;
    }
    cout<<"###############################"<<endl;
    cout<<endl;
}