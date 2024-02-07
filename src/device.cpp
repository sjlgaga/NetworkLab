#include <iostream>
#include <cstring>
#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "routing.h"
using namespace std;
vector <pcap_if_t*> mydevice;
vector <in_addr> IPaddr;
vector <char*> MACaddr;
vector <char*> IPname;
vector <string> mmacaddr;

int initDevice()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs,errbuf)==-1)
    {
        cerr<<"Error in pcap_findalldevs:"<<errbuf<<endl;
        return -1;
    }

    pcap_if_t* curdev;
    for (curdev=alldevs;curdev!=NULL;curdev=curdev->next)
    {
        cout<<"Already existed device:"<<curdev->name<<endl;
    }
    pcap_freealldevs(alldevs);

    return 1;
}

int addDevice(const char* device)
{
    if (findDevice(device)!=-1)
    {
        return findDevice(device);
    }

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs,errbuf)==-1)
    {
        cerr<<"Error in pcap_findalldevs:"<<errbuf<<endl;
        return -1;
    }

    pcap_if_t* curdev;
    for (curdev=alldevs;curdev!=NULL;curdev=curdev->next)
    {
        if (strcmp(curdev->name,device)==0)
        {

            for(pcap_addr_t *a=curdev->addresses; a!=NULL; a=a->next) 
            {
                if(a->addr->sa_family == AF_INET)
                {
                    in_addr ip;
                    memcpy(&ip,&(((struct sockaddr_in*)a->addr)->sin_addr),sizeof(struct in_addr));
                    IPaddr.push_back(ip);
                    break;
                }
                    
            }
            pcap_if_t* newdev=new pcap_if_t;
            newdev->addresses=new pcap_addr;
            memcpy(newdev->addresses,curdev->addresses,sizeof(pcap_addr));
            newdev->addresses->addr=new sockaddr;
            memcpy(newdev->addresses->addr,curdev->addresses->addr,sizeof(struct sockaddr));
            
            newdev->name=new char[strlen(curdev->name)];
            strcpy(newdev->name,curdev->name);

            newdev->description=new char[100];
            const char* addmsg="new added device";
            memcpy(newdev->description,addmsg,strlen(addmsg));
            
            newdev->flags=curdev->flags;
   
            int devnum=mydevice.size();
            if(devnum!=0)
            {
                mydevice[devnum-1]->next=newdev;
            }
            
            mydevice.push_back(newdev);
            pcap_freealldevs(alldevs);

            return devnum;
        }
    }
    pcap_freealldevs(alldevs);
    return -1;
}

int findDevice(const char* device)
{
    int cnt;
    int devnum=mydevice.size();
    for (cnt=0;cnt<devnum;cnt++)
    {
        if (strcmp(mydevice[cnt]->name,device)==0)
        {
            return cnt;
        }
    }
    return -1;
}

int setIPandMAC()
{
    int devnum=mydevice.size();
    for (int i=0;i<devnum;i++)
    {

            in_addr ip;
            get_myIP(&ip,i);
            IPaddr.push_back(ip);
            char s[INET_ADDRSTRLEN];
            inet_ntop(AF_INET,&ip,s,INET_ADDRSTRLEN);
            IPname.push_back(s);
            char mac[18]={0};
            get_myMAC(i,mac);
            MACaddr.push_back(mac);
    }
    return 1;
}