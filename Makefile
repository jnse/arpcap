CPP=g++
#CPPFLAGS=-std=c++11 -Wall -o3 -march=native
CPPFLAGS=-std=c++11 -Wall -o0 -ggdb

all: clean arpcap

clean:
	rm -f arpcap *.o

arpcap: arpcap.o
	$(CPP) $(CPPFLAGS) arpcap.o -o arpcap

arpcap.o:
	$(CPP) $(CPPFLAGS) -c arpcap.cpp -o arpcap.o
