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
    
int main(int argc, char*argv[])
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
     this_thread::sleep_for(chrono::seconds(150));
    
}