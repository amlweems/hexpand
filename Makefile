CC        = clang
CFLAGS    = -Wall -Werror -Wno-deprecated-declarations
LDFLAGS   = 

SOURCES   = hexpand.c main.c
OBJECTS   = ${SOURCES:.c=.o}

EXECUTABLE = hexpand

CFLAGS    += $(shell pkg-config --cflags openssl)
LDFLAGS   += $(shell pkg-config --libs openssl)

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o: $(OBJECTS)
	$(CC) -c $(CFLAGS) $< -o $@

test: $(EXECUTABLE)
	./$(EXECUTABLE) --test

clean:
	rm $(OBJECTS) $(EXECUTABLE)
