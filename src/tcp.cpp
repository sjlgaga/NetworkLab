#include "socket.h"
#include "ip.h"
#include <thread>
#include <chrono>
#include <functional>
using namespace std;
extern map<int,Socketfd*>Sockets;
int sendTCPSegment(int fd)
{
    auto sockfd=get_socket(fd);
    if (sockfd==nullptr)
    {
        cerr<<"ji!"<<endl;
        return -1;
    }
    Connect* cot=sockfd->connect;
    u_char segment[IP_MAXPACKET-24];
    tcphdr tcpHeader;
    cot->cotlock.lock();
    tcpHeader.th_sport=htons(cot->myaddr.sin_port);
    tcpHeader.th_dport=htons(cot->aiteaddr.sin_port);
    tcpHeader.th_seq=htonl(cot->curseq);
    tcpHeader.th_ack=htonl(cot->curack);
    tcpHeader.th_off=5;
    tcpHeader.th_win=htons(4096);
    tcpHeader.th_sum=0;
    tcpHeader.th_urp=0;

    int state=cot->state;
    in_addr src=cot->myaddr.sin_addr;
    in_addr dst=cot->aiteaddr.sin_addr;
    int len=cot->sendbuflen;
    uint8_t flag=cot->flag;
    cot->nextseq=cot->curseq+len;
    tcpHeader.th_flags=flag;
    memcpy(segment,&tcpHeader,sizeof(tcpHeader));
    memcpy(segment+sizeof(tcpHeader),cot->sendbuf,len);
    cot->cotlock.unlock();

    if (state==1)
    {
        while(cot->state!=3)
        {
            sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
            this_thread::sleep_for(chrono::seconds(5));
        }
    }
    else if(state==2)
    {
        while(cot->state!=3)
        {
            sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
            this_thread::sleep_for(chrono::seconds(5));
        }
    }
    else if (state==3)
    {
        if ((flag&TH_PUSH)!=0)
        {
            while(cot->curseq!=cot->nextseq)
            {   
                cout<<endl<<"PUSH ACK "<<"current sequence number:"<<cot->curseq<<" current ack number:"<<cot->curack<<endl;
                sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
                this_thread::sleep_for(chrono::seconds(5));
            }
        }
        else
        {
            cout<<endl<<"ACK "<<"current sequence number:"<<cot->curseq<<" current ack number:"<<cot->curack<<endl;
            sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
        }
        
    }
    else if (state==4)
    {
        while(cot->state!=6)
        {
            sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
            this_thread::sleep_for(chrono::seconds(5));
        }
    }
    else if (state==6)
    {
        sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
    }
    else if (state==7)
    {
        while(cot->state!=8)
        {
            sendIPPacket(src,dst,IPPROTO_TCP,segment,len+sizeof(tcpHeader));
            this_thread::sleep_for(chrono::seconds(5));
        }
    }
    return 1;

}

int find_socket(in_port_t port)
{
    for (auto it=Sockets.begin();it!=Sockets.end();it++)
    {
        if (it->second->connect->myaddr.sin_port==port)
            return it->first;
    }
    return -1;
}

int TCPhandler(in_addr srcip,in_addr destip,const void* buf, int len)
{
    struct tcphdr* tcpHeader=(struct tcphdr*) buf;
    in_port_t sport=ntohs(tcpHeader->th_sport);
    in_port_t dport=ntohs(tcpHeader->th_dport);
    uint32_t seq=ntohl(tcpHeader->th_seq);
    uint32_t ack=ntohl(tcpHeader->th_ack);
    int socknum=find_socket(dport);
    auto sockfd=get_socket(socknum);
    if (sockfd==nullptr)
    {
        return -1;
    }
    if (sockfd->state==3)
    {
        return listening_handler(socknum,srcip,destip,buf,len);
    }

    Connect* cot=sockfd->connect;
    if (sockfd->state==4)
    {
        return start_handler(socknum,buf,len);
    }
    
    if (sockfd->state==5||sockfd->state==6)
    {
        return established_hanler(socknum,buf,len);
    }

    if (sockfd->state==7)
    {
        return end_handler(socknum,buf,len);
    }

    
    

    return 1;
}

int listening_handler(int socknum,in_addr srcip,in_addr destip,const void* buf, int len)
{
    struct tcphdr* tcpHeader=(struct tcphdr*) buf;
    in_port_t sport=ntohs(tcpHeader->th_sport);
    in_port_t dport=ntohs(tcpHeader->th_dport);
    uint32_t seq=ntohl(tcpHeader->th_seq);
    uint32_t ack=ntohl(tcpHeader->th_ack);
    auto sockfd=get_socket(socknum);
    if (sockfd->listen_queue.size()>=sockfd->backlog)
            return -1;
    Connect* newcot=new Connect();

    newcot->myaddr.sin_family=AF_INET;
    newcot->myaddr.sin_addr.s_addr=srcip.s_addr;
    newcot->myaddr.sin_port=sport;

    newcot->aiteaddr.sin_family=AF_INET;
    newcot->aiteaddr.sin_addr.s_addr=destip.s_addr;
    newcot->aiteaddr.sin_port=dport;

    newcot->curseq=seq;
    newcot->curack=ack;
    newcot->state=1;

    sockfd->listen_queue.push_back(newcot);
    return 1;
}

int start_handler(int socknum,const void* buf, int len)
{
    auto sockfd=get_socket(socknum);
    Connect* cot=sockfd->connect;
    bool send=false;
    uint8_t flag=0;
    struct tcphdr* tcpHeader=(struct tcphdr*) buf;
    in_port_t sport=ntohs(tcpHeader->th_sport);
    in_port_t dport=ntohs(tcpHeader->th_dport);
    uint32_t seq=ntohl(tcpHeader->th_seq);
    uint32_t ack=ntohl(tcpHeader->th_ack);

    cot->cotlock.lock();
    if (cot->state==0)
    {
        if ((tcpHeader->th_flags&TH_SYN)!=0)
        {
            cot->state=2;
            cot->curseq=1;
            cot->curack=seq+1;
            send=true;
            flag|=TH_SYN;
            flag|=TH_ACK;
        }
        
    }
    else if (cot->state==1)
    {
        if ((tcpHeader->th_flags&TH_SYN)!=0&&(tcpHeader->th_flags&TH_ACK)!=0&&ack==cot->curseq+1)
        {
            cot->curseq=ack;
            cot->curack=seq+1;

            cot->aiteaddr.sin_port=sport;

            cot->state=3;
            sockfd->state=6;
            send=true;
            flag|=TH_ACK;
        }
        
        
    }
    else if (cot->state==2)
    {
        if ((tcpHeader->th_flags&TH_ACK)!=0&&tcpHeader->th_ack==cot->curseq+1)
        {
            cot->curseq=tcpHeader->th_ack;
            cot->curack=tcpHeader->th_seq+1;
            cot->state=3;
            sockfd->state=6;
        }
        
    }

    cot->flag=flag;
    memset(cot->sendbuf,0,sizeof(cot->sendbuf));
    cot->sendbuflen=0;
    cot->cotlock.unlock();
   if (send)
   {
        cout<<"send ack"<<endl;
        auto sendthread=thread(sendTCPSegment,socknum);
        sendthread.detach();
   }
    

    return 1;
}

int established_hanler(int socknum,const void* buf, int len)
{
    auto sockfd=get_socket(socknum);
    Connect* cot=sockfd->connect;
    bool send=false;
    uint8_t flag=0;
    struct tcphdr* tcpHeader=(struct tcphdr*) buf;
    in_port_t sport=ntohs(tcpHeader->th_sport);
    in_port_t dport=ntohs(tcpHeader->th_dport);
    uint32_t seq=ntohl(tcpHeader->th_seq);
    uint32_t ack=ntohl(tcpHeader->th_ack);

    cot->cotlock.lock();

    cout<<endl<<"nextseq "<<cot->nextseq<<endl;
    if (((tcpHeader->th_flags&TH_ACK)!=0||(tcpHeader->th_flags&TH_SYN)!=0||(tcpHeader->th_flags&TH_FIN)!=0)&&ack==cot->nextseq)
    {
        cout<<endl<<"address push ack "<<"recv seq num "<<seq<<"recv ack num "<<ack<<endl;
        cot->curseq=ack;
        cot->curack=seq+len-sizeof(struct tcphdr);
        if ((tcpHeader->th_flags&TH_PUSH)!=0)
        {
            if (cot->curack>seq)
            send=true;
            flag|=TH_ACK;
        }
    }
    cot->flag=flag;
    memset(cot->sendbuf,0,sizeof(cot->sendbuf));
    cot->sendbuflen=0;
    
    u_char* payload=(u_char*)buf+sizeof(tcphdr);
    int paylen=len-(int)sizeof(struct tcphdr);
    if (paylen!=0&&(tcpHeader->th_flags&TH_PUSH)!=0)
    {
        if (cot->writept+paylen<cot->recvbuf+10*(IP_MAXPACKET-24))
        {
            memcpy(cot->writept,payload,paylen);
            cot->writept+=paylen;
        }
        else
        {
            size_t old_size=(size_t)(cot->writept-cot->readpt);
            memcpy(cot->recvbuf,cot->readpt,old_size);
            cot->readpt=cot->recvbuf;
            cot->writept=cot->readpt+old_size;
            if (cot->writept+paylen>=cot->recvbuf+10*(IP_MAXPACKET-24))
            {
                cerr<<"buffer not enough!"<<endl;
                return -1;
            }
            memcpy(cot->writept,payload,paylen);
            cot->writept+=paylen;
        }
       
    }


    cot->cotlock.unlock();
    if (send)
   {
        cout<<"send ack"<<endl;
        auto sendthread=thread(sendTCPSegment,socknum);
        sendthread.detach();
   }
   return 1;
}

int end_handler(int socknum,const void* buf, int len)
{
    auto sockfd=get_socket(socknum);
    bool send=false;
    uint8_t flag=0;
    struct tcphdr* tcpHeader=(struct tcphdr*) buf;
    in_port_t sport=ntohs(tcpHeader->th_sport);
    in_port_t dport=ntohs(tcpHeader->th_dport);
    uint32_t seq=ntohl(tcpHeader->th_seq);
    uint32_t ack=ntohl(tcpHeader->th_ack);

    Connect* cot=sockfd->connect;
    cot->cotlock.lock();

    if (cot->state==4)
    {
        if ((tcpHeader->th_flags&TH_FIN)!=0&&(tcpHeader->th_flags&TH_ACK)!=0&&ack==cot->curseq+1)
        {
            cot->curack=seq+1;
            cot->curseq=ack;
            send=true;
            flag=TH_ACK;
            cot->state=6;
            auto endthread=thread(wait_to_close,socknum);
            endthread.detach();
        }
    }
    else if (cot->state==5)
    {
        if ((tcpHeader->th_flags&TH_FIN)!=0)
        {
            cot->curack=seq+1;
            send=true;
            flag=TH_ACK|TH_FIN;
            cot->state=7;
        }
    }
    else if (cot->state==7)
    {
        if ((tcpHeader->th_flags&TH_ACK)!=0&&ack==cot->curseq+1)
        {
            cot->state=8;
            sockfd->state=9;
        }
    }

    cot->flag=flag;
    memset(cot->sendbuf,0,sizeof(cot->sendbuf));
    cot->sendbuflen=0;
    cot->cotlock.unlock();
    if (send)
   {
        cout<<"send ack"<<endl;
        auto sendthread=thread(sendTCPSegment,socknum);
        sendthread.detach();
   }
}

int wait_to_close(int socknum)
{
    this_thread::sleep_for(chrono::seconds(120));
    auto sockfd=get_socket(socknum);
    Connect* cot=sockfd->connect;
    cot->state=8;
    sockfd->state=9;
    return 1;
}