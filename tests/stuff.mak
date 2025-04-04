CC = gcc
CFLAGS = -c -Wall
LDFLAGS = -lssl -lcrypto
OBJECTS = test_server.o network.o crypto.o
EXECUTABLE = test_server

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

test_server.o: test_server.c network.h crypto.h
	$(CC) $(CFLAGS) test_server.c -o $@

network.o: network.c network.h
	$(CC) $(CFLAGS) network.c -o $@ $(LDFLAGS)

crypto.o: crypto.c crypto.h
	$(CC) $(CFLAGS) crypto.c -o $@ $(LDFLAGS)

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)

.PHONY: all clean
