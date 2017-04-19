// nat entry:
//   Translated port
//   Internal address pair, i.e IP and port
//   TCP state
#define ACTIVE 0
#define FIN1_SENT 1
#define FIN1_RECEIVED 2
#define ACK1_SENT 3
#define ACK1_RECEIVED 4
#define FIN2_SENT 5
#define FIN2_RECEIVED 6


// struct for enrty
typedef struct nat_entry{
    unsigned short t_port;          //translated port
    unsigned short i_port;          //Internal port
    unsigned long i_addr;           //Internal IP
    int tcp_state;                //TCP state ??????
}nat_e;

// struct for table

nat_e **entry_list;


//Desirable functions

nat_e **create_table();      //create a new translation entry
nat_e *searchSource(nat_e **table, unsigned long addr, unsigned short port);
nat_e *searchDest(nat_e **table, unsigned short port);
nat_e *insert(nat_e **table, unsigned long addr, unsigned short port);
void drop(nat_e **table, unsigned short port);
