
#satura make file
CC=gcc
APP=prg2_satura-dos
all: prg2_satura-dos

prg2_satura-dos:
	$(CC) -std=c99 -ggdb -Wcpp -Wall -pthread -lpcap -lrt `libnet-config --defines` $(APP).c `libnet-config --libs` -o $(APP)
clean:
	rm -f *.o *.out $(APP)
