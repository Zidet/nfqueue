#include <stdio.h>
#include <stdlib.h>
#include "nat_table.h"

nat_e **create_table(){
    entry_list=(nat_e*)malloc(sizeof(nat_e*)*2001);
    return entry_list;
}

// search the source IP-port pair
// if not exist, return null, else return that entry
nat_e *searchSource(nat_e **table, unsigned long addr, unsigned short port){
    // nat_entry *ne_l=NULL;
    // for (ne_l=table->next_addr; ne_l != NULL && ne_l->i_addr != addr; ne_l=ne_l->next_addr);
    // for (;ne_l != NULL && ne_l->i_port != port; ne_l=ne_l->next_port);
    // return ne_l;
    nat_e *ne_new=NULL;
    int i;
    for (i=0;i<2001&&table[i]->i_addr!=addr&&table[i]->i_port!=port&&table[i]!=NULL;i++);
    return table[i];
}
nat_e *searchDest(nat_e **table, unsigned short port){
    // if(table && port>=10000&&port<=12000)
    //   return table->entry_list[port-10000];
    // return NULL;
    return table[port-10000];
}
nat_e *insert(nat_e **table, unsigned long addr, unsigned short port){
    nat_e *ne_l = (nat_e*)malloc(sizeof(nat_e));
    ne_l->i_addr=addr;
    ne_l->i_port=port;
    ne->tcp_state="ACTIVE";
    int i = 0;
    while(1){
      if (tabile->entry_list[i]==NULL) break;
      i++;
    }
    int tp=i+10000;
    ne_l->t_port=tp;
    table[i]=ne_l;
  //   tmp=table->next_addr;
  //   while(1){
  //     if (tmp==NULL) tmp=ne_l;
  //     else if(tmp!=NULL && tmp->addr!=addr) tmp=tmp->next_addr;
  //     else if(tmp!=NULL && tmp->addr==addr){
  //       ne->next_port=tmp->next_port;
  //       tmp->next_port=ne;
  //     }
  // }
    return ne_l;
}
