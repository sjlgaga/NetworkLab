#include <vector>
#define ROUTESET 2
struct dv_node
{
    struct in_addr dst;
    struct in_addr dst_mask;
    int hopnum;
};

struct FD_table
{
    struct in_addr dst;
    struct in_addr dst_mask;
    struct in_addr nexthop;
    int id;
};

extern std::vector<dv_node> dv;
extern std::vector<FD_table> fd_table;

int sendRoutePacket(const struct in_addr src, const struct in_addr dest, int proto, const void *buf, int len,int id);
int send_dv();
int init_dv();
int recv_route(const in_addr src,const void* buf,int len, int id);
int setRouteTable();
void printFDtable();
void printDV();
void printRTtable();
void printARPtable();