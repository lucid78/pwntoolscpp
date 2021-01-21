GCC=/usr/bin/g++
CFLAGS= -c -pipe -O2 -std=gnu++1z -Wall -Wextra -fPIC
OBJS= main.o
TARGET=pwntools_test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(GCC) -Wl,-rpath,../ -O1 -o $(TARGET) main.o  -L. -L../ -lpwntoolscpp -lpthread

main.o : main.cpp
	$(GCC) $(CFLAGS) -o main.o main.cpp -I. -I../

clean:
	rm -f *.o *.core *~
	rm -f $(TARGET)

