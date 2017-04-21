all:
	gcc -o nat nat.c checksum.c checksum.h nat_table.c nat_table.h -lnfnetlink -lnetfilter_queue
clean:
	@em -f nftest
