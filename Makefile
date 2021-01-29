SRC = tuntap.cc main.cc
OBJ = tuntap.o  main.o

BIN = tuntest
LIBS = -lpthread

CXXFLAGS += -W -Wall -O2

ifeq ($(DEBUG),y)
CPPFLAGS += -DDEBUG -g
endif

all : $(BIN)

clean :
	rm -f $(BIN)
	rm -f *.o core.* *~

.PHONY : all clean

$(BIN) : $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(BIN) $(LIBS) $+

tuntap.o: tuntap.cc tuntap.h
main.o: main.cc
