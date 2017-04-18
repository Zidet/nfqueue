// nat entry:
//   Translated port
//   Internal address pair, i.e IP and port
//   TCP state


// struct for enrty
typedef struct nat_entry{
    unsigned short t_port;          //translated port
    unsigned short i_port;          //Internal port
    unsigned long i_addr;           //Internal IP
    char *tcp_state;                //TCP state ??????
}nat_e;

// struct for table

nat_e **entry_list;


//Desirable functions

nat_t *create_table();      //create a new translation entry
nat_e *searchSource(nat_e **table, unsigned long addr, unsigned short port);
nat_e *searchDest(nat_e **table, unsigned short port);
nat_e *insert(nat_e **table, unsigned long addr, unsigned short port);
void drop(nat_e **table, unsigned short port);
