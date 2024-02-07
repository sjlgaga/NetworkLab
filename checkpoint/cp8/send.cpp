#include <iostream>
#include <cstring>
#include <thread>
#include <chrono>
#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "routing.h"
#include "socket.h"
using namespace std;
int main(int argc,char*argv[])
{
    for (int i=1;i<argc;i++)
    {
        addDevice(argv[i]);
    }
    int devnum=mydevice.size();

    for (int i=0;i<devnum;i++)
    {
            
            char mac[18]={0};
            get_myMAC(i,mac);
            string s="";
            for (int i=0;i<18;i++)
            {
                s+=mac[i];
            }
            mmacaddr.push_back(s);
            
    }
        
    for (int i=0;i<mydevice.size();i++)
    {
        cout<<mydevice[i]->name<<" "<<IPaddr[i].s_addr<<" "<<(char*)mmacaddr[i].c_str()<<endl;
    }
    thread threads[argc-1];
    for (int i=0;i<argc-1;i++)
    {
        threads[i]=thread(FrameReceiveCallback,mydevice[i]->name);
        threads[i].detach();
    }
    this_thread::sleep_for(chrono::seconds(3));
    init_dv();
    this_thread::sleep_for(chrono::seconds(3));
    setRouteTable();
    this_thread::sleep_for(chrono::seconds(3));
    printRTtable();

    int clfd=__wrap_socket(AF_INET, SOCK_STREAM, 0);
    auto sockfd=get_socket(clfd);
    sockfd->connect=new Connect();
    Connect* cot=sockfd->connect;
    cot->state=3;
    cot->myaddr.sin_family=AF_INET;
    cot->myaddr.sin_addr.s_addr=IPaddr[0].s_addr;
    cot->myaddr.sin_port=12345;

    in_addr dst;
    const char* dststring="10.100.3.2";
    inet_pton(AF_INET,dststring,&dst);
    cot->aiteaddr.sin_family=AF_INET;
    cot->aiteaddr.sin_addr.s_addr=dst.s_addr;
    cot->aiteaddr.sin_port=80;

    cot->curseq=1;
    cot->curack=0;
    cot->writept=cot->recvbuf;
    cot->readpt=cot->recvbuf;

    for (int i=0;i<argc-1;i++)
    {

        const char* s="In these examples, inet_ntop is used to convert the binary representation of an IP address into a human-readable string. The resulting string is stored in the ipStr variable.";

        for (int i=0;i<10;i++)
        {
            cot->cotlock.lock();
            cot->sendbuflen=strlen(s);
            memcpy(cot->sendbuf,s,cot->sendbuflen);
            cot->flag=TH_PUSH|TH_ACK;
            cot->cotlock.unlock();
            sendTCPSegment(clfd);
        }
            
    }
    this_thread::sleep_for(chrono::seconds(150));

}