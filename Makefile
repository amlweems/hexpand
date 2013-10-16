CC        = gcc
CFLAGS    = -Wall -ggdb
LDFLAGS   = 

SOURCES   = hexpand.c
OBJECTS   = ${SOURCES:.c=.o}

EXECUTABLE = hexpand

CFLAGS    += $(shell pkg-config --cflags openssl)
LDFLAGS   += $(shell pkg-config --libs openssl)

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o: $(OBJECTS)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm $(OBJECTS) $(EXECUTABLE)
