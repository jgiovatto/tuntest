SRC = tuntap.cc main.cc netutils.cc dvmrp.cc
OBJ = tuntap.o  main.o netutils.o dvmrp.o

BIN = tuntest

CXXFLAGS += -W -Wall -Wextra -O2 -g0 --std=c++11

ifeq ($(DEBUG),y)
CPPFLAGS += -DDEBUG -g3 -O0
endif

all : $(BIN)

clean :
	rm -f $(BIN)
	rm -f *.o core.* *~

.PHONY : all clean

$(BIN) : $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(BIN) $(LIBS) $+

tuntap.o: tuntap.cc tuntap.h
main.o: main.cc dvmrp.h tuntap.h netutils.h
netutils.o: netutils.cc netutils.h
dvmrp.o: dvmrp.cc dvmrp.h netutils.h
