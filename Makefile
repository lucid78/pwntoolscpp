GCC=/usr/bin/g++
CFLAGS= -c -pipe -O2 -std=gnu++1z -Wall -Wextra -fPIC
OBJS= elf.o process.o utility.o
TARGET=libpwntoolscpp.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(GCC) -shared -Wl,-soname,$(TARGET) -o $(TARGET) $(OBJS) -L/usr/local/lib/ -lpthread -lboost_thread -lboost_chrono

elf.o : elf.cpp
	$(GCC) $(CFLAGS) -o elf.o elf.cpp -I.

process.o : process.cpp
	$(GCC) $(CFLAGS) -o process.o process.cpp -I.

utility.o : utility.cpp
	$(GCC) $(CFLAGS) -o utility.o utility.cpp -I.

clean:
	rm -f *.o *.core *~
	rm -f $(TARGET)
