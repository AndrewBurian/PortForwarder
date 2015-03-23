# generic makefile
CC=gcc
CFLAGS=-c -g -O0 -Wall
LDFLAGS=
LIBS=-lconfread
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=portforward.exe

SOURCES=main.c forward.c checksum.c firewall_rules.c

all: $(SOURCES) $(EXECUTABLE)

valgrind: $(SOURCES) $(EXECUTABLE)
	valgrind --leak-check=full --show-possibly-lost=no ./$(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
