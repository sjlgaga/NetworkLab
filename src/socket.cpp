#include "socket.h"
#include "device.h"
#include <iostream>
#include <cstring>
#include <string>
#include <mutex>
#include <cstdlib>
using namespace std;

const int SocketStart=1000;
int SocketIndex=1001;
map<int,Socketfd*> Sockets;
mutex socketlock;
int __wrap_socket(int domain, int type, int protocol)
{
    if (domain!=AF_INET||type!=SOCK_STREAM||protocol!=0)
        return socket(domain,type,protocol);

    Socketfd* newsocket=new Socketfd();
    newsocket->fd=SocketIndex;
    SocketIndex++;
    newsocket->state=1;
    newsocket->connect=nullptr;
    memset(&newsocket->addr,0,sizeof(sockaddr_in));
    socketlock.lock();
    Sockets[newsocket->fd]=newsocket;
    socketlock.unlock();

    return newsocket->fd;

}

Socketfd* get_socket(int fd)
{
    socketlock.lock();
    auto iter=Sockets.find(fd);
    if (iter==Sockets.end())
    {
        socketlock.unlock();
        return nullptr;
    }
    else
    {
        socketlock.unlock();
        return iter->second;
    }
}

int __wrap_bind(int socket , const struct sockaddr *address ,
socklen_t address_len)
{
    if (socket<SocketStart)
        return bind(socket,address,address_len);
    
    auto sockfd=get_socket(socket);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }
    if (sockfd->state!=1)
    {
        errno=EINVAL;
        cerr<<"not a default socket"<<endl;
        return -1;
    }

    sockaddr_in *addr=(sockaddr_in*) address;
    sockfd->addr.sin_family=AF_INET;
    sockfd->addr.sin_addr.s_addr=IPaddr[0].s_addr;
    sockfd->addr.sin_port=addr->sin_port;
    sockfd->state=2;

    return 0;
    
}

int __wrap_listen(int socket , int backlog)
{
    if (socket<SocketStart)
        return listen(socket,backlog);
    auto sockfd=get_socket(socket);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }
    if (sockfd->state!=2)
    {
        cerr<<"not a bind socket!"<<endl;
        errno=EINVAL;
        return -1;
    }

    sockfd->state=3;
    sockfd->backlog=backlog;
    return 0;
}

int __wrap_accept(int socket , struct sockaddr *address , socklen_t *address_len)
{
    if (socket<SocketStart)
        return accept(socket,address,address_len);

    auto sockfd=get_socket(socket);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }
    if (sockfd->state!=3)
    {
        cerr<<"not a listening socket!"<<endl;
        errno=EINVAL;
        return -1;
    }

    int newnum=__wrap_socket(AF_INET,SOCK_STREAM,0);
    auto newfd=get_socket(newnum);
    socklen_t len;
    memcpy(&len,address_len,sizeof(len));
    if (address!=nullptr)
        __wrap_bind(newnum,address,len);
    if (sockfd->listen_queue.size()==0)
    {
        cerr<<"listening queue empty"<<endl;
        return -1;
    }
    auto request=sockfd->listen_queue[0];


    newfd->state=4;
    newfd->connect=new Connect();
    newfd->connect->state=0;
    newfd->connect->curseq=1;
    newfd->connect->curack=request->curseq+1;

    newfd->connect->myaddr.sin_family=AF_INET;
    newfd->connect->myaddr.sin_addr.s_addr=sockfd->addr.sin_addr.s_addr;
    newfd->connect->myaddr.sin_port=10000+rand();

    newfd->connect->aiteaddr.sin_family=AF_INET;
    newfd->connect->aiteaddr.sin_addr.s_addr=request->myaddr.sin_addr.s_addr;
    newfd->connect->aiteaddr.sin_port=request->myaddr.sin_port;
    sockfd->listen_queue.pop_front();

    Connect* cot=newfd->connect;
    cot->state=2;
    memset(cot->sendbuf,0,sizeof(cot->sendbuf));
    cot->sendbuflen=0;
    cot->flag=TH_SYN|TH_ACK;
    cot->readpt=cot->recvbuf;
    cot->writept=cot->recvbuf;
    sendTCPSegment(newnum);

    return newnum;

}

int __wrap_connect(int socket , const struct sockaddr *address , socklen_t address_len)
{
    if (socket<SocketStart)
        return connect(socket,address,address_len);

    auto sockfd=get_socket(socket);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }
    if (sockfd->state!=1)
    {
        cerr<<"not a default socket!"<<endl;
        errno=EINVAL;
        return -1;
    }

    sockaddr_in* addr=(sockaddr_in*)address;
    sockfd->state=4;
    sockfd->connect=new Connect();
    Connect* cot=sockfd->connect;
    cot->state=1;
    cot->curseq=1;
    cot->curack=1;

    cot->myaddr.sin_family=AF_INET;
    cot->myaddr.sin_addr.s_addr=IPaddr[0].s_addr;
    cot->myaddr.sin_port=10000+rand();

    cot->aiteaddr.sin_family=AF_INET;
    cot->aiteaddr.sin_addr.s_addr=addr->sin_addr.s_addr;
    cot->aiteaddr.sin_port=addr->sin_port;

    memset(cot->sendbuf,0,sizeof(cot->sendbuf));
    cot->sendbuflen=0;
    cot->flag=TH_SYN;
    cot->readpt=cot->recvbuf;
    cot->writept=cot->recvbuf;
    sendTCPSegment(socket);

    //sendTCPSegment(sockfd->connect,TH_PUSH,nullptr,0);
    return 1;
}

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte)
{
    if (fildes<SocketStart)
        return read(fildes,buf,nbyte);
    auto sockfd=get_socket(fildes);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }
    if (sockfd->state!=5)
    {
        cerr<<"socket state not established"<<endl;
        return -1;
    }

    Connect* cot=sockfd->connect;
    if (cot->state!=3)
    {
        cerr<<"tcp connection not established"<<endl;
        return -1;
    }
    size_t upmost=IP_MAXPACKET/2;
    size_t needbyte=nbyte;
    while(needbyte>upmost)
    {
        if (cot->writept>=cot->readpt+upmost)
        {
            memcpy(buf,cot->readpt,upmost);
            cot->readpt+=upmost;
        }
        else
        {
            cerr<<"wait for the content! There is no enough message"<<endl;
            return -1;
        }
        needbyte-=upmost;
    }

    if (cot->writept>=cot->readpt+needbyte)
        {
            memcpy(buf,cot->readpt,needbyte);
            cot->readpt+=needbyte;
            return nbyte;
        }
        else
        {
            cerr<<"wait for the content! There is no enough message"<<endl;
            return -1;
        }
}

ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte)
{
    if (fildes<SocketStart)
        return write(fildes,buf,nbyte);

    auto sockfd=get_socket(fildes);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }
    if (sockfd->state!=5)
    {
        cerr<<"socket state not established"<<endl;
        return -1;
    }

    Connect* cot=sockfd->connect;
    if (cot->state!=3)
    {
        cerr<<"tcp connection not established"<<endl;
        return -1;
    }

    size_t upmost=IP_MAXPACKET/2;
    size_t needbyte=nbyte;
    u_char* buff=(u_char*)buf;
    while(needbyte>upmost)
    {
        cot->cotlock.lock();
        cot->sendbuflen=upmost;
        memcpy(cot->sendbuf,buff,upmost);
        cot->cotlock.unlock();
        sendTCPSegment(fildes);
        buff+=upmost;
        needbyte-=upmost;
    }
    cot->cotlock.lock();
    cot->sendbuflen=needbyte;
    memcpy(cot->sendbuf,buff,needbyte);
    cot->cotlock.unlock();
    sendTCPSegment(fildes);
    
    return nbyte;

}

int __wrap_close(int fildes)
{
    if (fildes<SocketStart)
        return close(fildes);
    auto sockfd=get_socket(fildes);
    if (sockfd==nullptr)
    {
        errno=EBADF;
        return -1;
    }

    if (sockfd->state==3)
    {
        sockfd->backlog=0;
        sockfd->listen_queue.clear();
        memset(sockfd->connect,0,sizeof(struct Connect));
        sockfd->state=9;
        return 1;
    }

    if (sockfd->state==5)
    {
        sockfd->state=7;
        Connect* cot=sockfd->connect;
        cot->cotlock.lock();
        cot->state=5;
        cot->flag=TH_FIN;
        cot->cotlock.unlock();
    }
    else if (sockfd->state==6)
    {
        sockfd->state=7;
        Connect* cot=sockfd->connect;
        cot->cotlock.lock();
        cot->state=4;
        cot->flag=TH_FIN;
        memset(cot->sendbuf,0,sizeof(cot->sendbuf));
        cot->sendbuflen=0;
        cot->cotlock.unlock();
        sendTCPSegment(fildes);
    }
    return 1;
}

int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints ,
struct addrinfo **res)
{
    return getaddrinfo(node,service,hints,res);
}