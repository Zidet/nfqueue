// basic include
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include<limits.h>

// network include
#include <linux/netfilter.h>  // for NF_ACCEPT
#include <linux/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// local include
#include "nat_table.h"
#include "checksum.h"

struct iphdr *ip;
struct tcphdr *tcp;
nfqnl_msg_packet_hdr *ph;

uint32_t publicIP;
uint32_t lanIP;
uint32_t subnetMask;
unsigned int mask = 0xFFFFFFFF; //255
int packet_num = 0;


int main(int argc, char ** argv){
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  struct nfq_handle *h;
  int fd,rv;
  char buf[4096];
  struct in_addr* inp = (in_addr*)malloc(sizeof(in_addr));

  if(argc!=4){
    printf("Usage: ./nat <public ip> <internal ip> <subnet mask>\n");
    exit(0);
  }

  // pre-processing
  inet_aton(argv[1],inp);
  publicIP = ntohl(inp->s_addr); // publicIP
  inet_aton(argv[2],inp);
  lanIP = ntohl(inp->s_addr);    // lanIP
  mask

}
