CPPFLAGS=-Wall -Wshadow -I. -O3
LDFLAGS=
CPP=g++


# Uncomment this if your system supports unaligned 32 bit pointers
CPPFLAGS+=-DUNALIGNED_32BIT

# Uncomment this if you want to debug TinyTUN
#CPPFLAGS+=-DEBUG -g



SRC=tinytun.cpp crypt.cpp conn.cpp server.cpp client.cpp tap.cpp


.PHONY:	all

all:	tinytun

clean:
	rm -f tinytun $(SRC:.cpp=.o)

tinytun: $(SRC:.cpp=.o)
	$(CPP) $(CPPFLAGS) -o $@ $(SRC:.cpp=.o) $(LDFLAGS)

%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c -o $@ $<
