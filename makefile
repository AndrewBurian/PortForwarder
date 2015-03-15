# generic makefile
CC=gcc
CFLAGS=-c -g -Wall
LDFLAGS=
LIBS=-lconfread
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=portforward.exe

SOURCES=main.c forward.c checksum.c

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
