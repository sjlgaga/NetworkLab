/**
* @file socket.h
* @brief POSIX-compatible socket library supporting TCP protocol on
IPv4. */
#include "tcp.h"
#include <sys/types.h> 
#include <sys/socket.h> 
#include <netdb.h>
#include <unistd.h>
#include <vector>
#include <deque>
#include <map>
using namespace std;
/**
* @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/socket.html)
*/
int __wrap_socket(int domain, int type, int protocol);
/**
* @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/bind.html)
*/
int __wrap_bind(int socket , const struct sockaddr *address ,
socklen_t address_len);
/**
* @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/listen.html)
*/
int __wrap_listen(int socket , int backlog);
/**
9
* @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/connect.html)
*/
int __wrap_connect(int socket , const struct sockaddr *address , socklen_t address_len);
/**
* @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/accept.html)
*/
int __wrap_accept(int socket , struct sockaddr *address , socklen_t *address_len);
/**
* @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/read.html)
*/
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);
/**
* @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/write.html)
*/
ssize_t __wrap_write(int fildes, const void *buf, size_t nbyte);
/**
* @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/ * 9699919799/functions/close.html)
*/
int __wrap_close(int fildes);
/**
* @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/
onlinepubs/
* 9699919799/functions/getaddrinfo.html) */
int __wrap_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints ,
struct addrinfo **res);


struct Socketfd
{
    int fd;
    sockaddr_in addr;
    int state;
    /*
    1:default just created
    2:passively been binded
    3:have been listening
    4:being in the process of setting establishment?
    5:passively established can be used
    6:activlye established can be used
    7:being in the process of closing establishment
    9:closed
    */

    Connect* connect;
    deque <Connect*> listen_queue;

    int backlog;
};


Socketfd* get_socket(int fd);