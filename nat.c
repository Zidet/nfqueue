// basic include
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

// network include
#include <netinet/in.h>
#include <linux/netfilter.h>  // for NF_ACCEPT
#include <linux/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

// local include
#include "nat_table.h"
#include "checksum.h"

struct iphdr *ip;
struct tcphdr *tcp;

uint32_t publicIP;
uint32_t lanIP;
uint32_t subnetMask;
uint32_t subnetIP;
unsigned int mask = 0xFFFFFFFF; //255
int packet_num = 0;

nat_e **table;

int TCPHandler(struct nfq_q_handle *qh,u_int32_t id,int payload_len,unsigned char *loadedData){
  uint32_t s_IP, d_IP; //s_Ip: source ip d_Ip: destination ip
  unsigned s_Port, d_Port, transport; //s_port: source port d_port: dest port
  //int isOutbound = 0;

  s_IP=ntohl(ip->saddr); 
  d_IP=ntohl(ip->daddr);

  s_Port=ntohs(tcp->source);
  d_Port=ntohs(tcp->dest);
  //printf("Mask Result: %d\n", s_IP&subnetMask);
  //printf("SubnetIP: %d\n", subnetIP); 
  //printf("OUTBOUND : %d\n", s_IP&subnetMask - subnetIP);
  //isOutbound = (s_IP&subnetMask - subnetIP == 0)? 0:1;
  //printf("ISOUTBOUND : %d\n",isOutbound);
  if((s_IP & subnetMask) == subnetIP){
    // outbound part
    printf("Outbound Packet\n");

    // search the entry in the nat table
    nat_e *entry;
    entry = searchSource(table, s_IP, s_Port);

    if(entry == NULL){

      printf("Entry not found\n");
      if(tcp->syn == 1){
        printf("Syn Packet\n");
        // insert new entry into the nat table
        if((entry = insert(table, s_IP, s_Port)) == NULL){
          fprintf(stderr, "Error: No empty entry in the NAT table\n");
          return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
        }

        transport = entry->t_port;
      }
      else{
        printf("Not Syn Packet\n");
        // drop the packet
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); //  is drop necessary?
      }
    }
    else{

      printf("Entry found\n");

      transport = entry->t_port;

      if(tcp->rst == 1){
        printf("RST Packet\n");
        // delete the entry
        drop(table, transport);
        entry = NULL;
      }

      else{
        // initiate a 4-way handshake
        if(entry->tcp_state == ACTIVE && tcp->fin == 1){
          printf("4-way handshake initiated: FIN1 sent\n");
          entry->tcp_state = FIN1_SENT;
        }

        // 4-way handshake initiated by the other side, expect to send an ACK or ACK+FIN2 packet
        else if(entry->tcp_state == FIN1_RECEIVED){
          if(tcp->ack != 1){
            fprintf(stderr, "Error: 4-way handshake error, expect to send an ACK/ACK-FIN packet\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
          }
          else{
            printf("4-way handshake in progress: ACK1 sent\n");
            entry->tcp_state = ACK1_SENT;
            if(tcp->fin == 1){
              printf("4-way handshake in progress: FIN2 sent\n");
              entry->tcp_state = FIN2_SENT;
            }
          }
        }

        // 4-way handshake initiated by the other side, expect to send an FIN2 packet
        else if(entry->tcp_state == ACK1_SENT){
          if(tcp->fin != 1){
            fprintf(stderr, "Error: 4-way handshake error, expect to send a FIN packet\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
          }
          else{
            printf("4-way handshake in progress: FIN2 sent\n");
            entry->tcp_state = FIN2_SENT;
          }
        }

        // 4-way handshake initiated by this side, expect to send an ACK2 packet, and close the connection
        else if(entry->tcp_state == FIN2_RECEIVED){
          if(tcp->ack != 1){
            fprintf(stderr, "Error: 4-way handshake error, expect to send an ACK packet\n");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
          }
          else{
            printf("4-way handshake ends: ACK2 SENT\n");
            drop(table, transport);
            entry = NULL;
          }
        }
      }

      // translate the source address
      ip->saddr = htonl(publicIP);
      tcp->source = htons(transport);

      // reset checksum
      ip->check = 0;
      tcp->check = 0;

      // calculate new checksum
      tcp->check = tcp_checksum((unsigned char *) ip); // correct?
      ip->check = ip_checksum((unsigned char *) ip);

      return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, loadedData);

    }


  }else{
    printf("Inbound Packet\n");
    //inbound part
    nat_e *entry;
    // int i;
    // for (i=0; i<2001; i++){
    //   if(table[i]==NULL){
    //     break;
    //   }
    //   else if(table[i].i_port==d_Port){
    //     entry=table[i];
    //     break;
    //   }
    // }
    entry=searchDest(table, d_Port);
    if(entry==NULL){
        puts("no Match!");
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
    else{
        puts("Match!");
        ip->daddr=htonl(entry->i_addr);
        tcp->dest=htons(entry->i_port);
        if (tcp->rst == 1){
          printf("RST PACKET");
          drop(table, transport);
          entry = NULL;
        }
        else{
          // initiate a 4-way handshake
          if(entry->tcp_state == ACTIVE && tcp->fin == 1){
            printf("4-way handshake initiated: FIN1 sent\n");
            entry->tcp_state = FIN1_RECEIVED;
          }

          // 4-way handshake initiated by the other side, expect to send an ACK or ACK+FIN2 packet
          else if(entry->tcp_state == FIN1_SENT){
            if(tcp->ack != 1){
              fprintf(stderr, "Error: 4-way handshake error, expect to send an ACK/ACK-FIN packet\n");
              return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
            }
            else{
              printf("4-way handshake in progress: ACK1 sent\n");
              entry->tcp_state = ACK1_RECEIVED;
              if(tcp->fin == 1){
                printf("4-way handshake in progress: FIN2 sent\n");
                entry->tcp_state = FIN2_RECEIVED;
              }
            }
          }

          // 4-way handshake initiated by the other side, expect to send an FIN2 packet
          else if(entry->tcp_state == ACK1_RECEIVED){
            if(tcp->fin != 1){
              fprintf(stderr, "Error: 4-way handshake error, expect to send a FIN packet\n");
              return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
            }
            else{
              printf("4-way handshake in progress: FIN2 sent\n");
              entry->tcp_state = FIN2_RECEIVED;
            }
          }

          // 4-way handshake initiated by this side, expect to send an ACK2 packet, and close the connection
          else if(entry->tcp_state == FIN2_SENT){
            if(tcp->ack != 1){
              fprintf(stderr, "Error: 4-way handshake error, expect to send an ACK packet\n");
              return nfq_set_verdict(qh, id, NF_DROP, 0, NULL); // is drop necessary?
            }
            else{
              printf("4-way handshake ends: ACK2 SENT\n");
              drop(table, transport);
              entry = NULL;
            }
          }
        }
    // reset checksum
		ip->check = 0;
		tcp->check = 0;

		// calculate new checksum
		tcp->check = tcp_checksum((unsigned char *) ip); // correct?
		ip->check = ip_checksum((unsigned char *) ip);

		return nfq_set_verdict(qh, id, NF_ACCEPT, payload_len, loadedData);
  }
  }
}

int Callback(struct nfq_q_handle *qh, struct nfgenmsg *msg, struct nfq_data *pkt, void *data){
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(pkt);
  unsigned long id=ntohl(ph->packet_id);
  char *loadedData;
  unsigned int data_len=nfq_get_payload(pkt, &loadedData);
  ip=(struct iphdr*) loadedData;
  if(ip->protocol==IPPROTO_TCP){
    tcp = (struct tcphdr *)(loadedData + (ip->ihl<<2));
    TCPHandler(qh,id,data_len, loadedData);
  }
  else{
    printf("received unTCP packet");
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  }
}
int main(int argc, char ** argv){
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd,len;
  char buf[4096];
  //struct in_addr* inp = (in_addr*)malloc(sizeof(in_addr));
  struct in_addr inp;
  int mask_int;

  if(argc!=4){
    printf("Usage: ./nat <public ip> <internal ip> <subnet mask>\n");
    exit(0);
  }

  table = create_table();

  // pre-processing
  inet_aton(argv[1],&inp);
  publicIP = ntohl(inp.s_addr); // publicIP
  inet_aton(argv[2],&inp);
  lanIP = ntohl(inp.s_addr);    // lanIP
  mask_int = atoi(argv[3]);
  subnetMask  = mask << (32-mask_int);
  subnetIP = lanIP & subnetMask;       // local_network(localIP);
  char* subnetIPStr = inet_ntoa(inp);
  printf("subnetIP: %s\n", subnetIPStr);


  // Open library handle
  if(!(h = nfq_open())){
    fprintf(stderr, "Error: nfq_open()\n");
    exit(-1);
  }
  if(nfq_bind_pf(h,AF_INET)<0){
    fprintf(stderr, "Error: nfq_bind_pf()\n");
    exit(-1);
  }
  if(!(qh = nfq_create_queue(h,0,&Callback,NULL))){
    fprintf(stderr, "Error: nfq_create_queue()\n");
    exit(-1);
  }
  if(nfq_set_mode(qh,NFQNL_COPY_PACKET, 0XFFFF)<0){
    fprintf(stderr, "Error: Could not set packet copy mode\n");
    exit(-1);
  }
  fd = nfq_fd(h);
  while((len = recv(fd,buf,sizeof(buf),0)) && len >= 0){
    nfq_handle_packet(h,buf,len);
  }

  // cleanup data structure
  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);
  nfq_close(h);
  return 0;
}
