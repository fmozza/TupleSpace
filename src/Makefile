#--------------------------------------------------------------------------
CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -g `pkg-config --cflags glib-2.0 sqlite3`
LDFLAGS = -lssl -lcrypto `pkg-config --libs glib-2.0 sqlite3` -pthread
SOURCES = tuple.c tuple_space.c tuple_server.c tuple_network.c tuple_encrypt.c tuple_keygen.c test_tuple_functions.c test_tuple_space_functions.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = tuple.h tuple_space.h tuple_network.h tuple_encrypt.h
TARGETS = tuple_server tuple_keygen test_sp test_tp

# Installation directories
PREFIX = /usr/local
INSTALL_DIR = $(PREFIX)/tuple_space
BIN_DIR = $(INSTALL_DIR)/bin
SQL_DIR = $(INSTALL_DIR)/sql
KEY_DIR = $(INSTALL_DIR)/.keys

# Database file (aligned with tuple_space.c)
DB_FILE = tuple_space.db

# Default server_id, overridable via command line or env
server_id ?= 01

# User and group for permissions (default to current user, override with make USER=someone)
USER ?= $(shell whoami)
GROUP ?= $(shell id -gn $(USER))

all: $(TARGETS)

# Tuple Server
tuple_server: tuple_server.o tuple_space.o tuple_network.o tuple_encrypt.o tuple.o
	$(CC) tuple_server.o tuple_space.o tuple_network.o tuple_encrypt.o tuple.o -o tuple_server $(LDFLAGS)

# Tuple Keygen
tuple_keygen: tuple_keygen.o tuple_encrypt.o
	$(CC) tuple_keygen.o tuple_encrypt.o -o tuple_keygen $(LDFLAGS)

# test_tp - test tuple functions
test_tp: test_tuple_functions.o tuple.o
	$(CC) tuple.o  test_tuple_functions.o -o test_tp $(LDFLAGS)

# test_tp - test tuple functions
test_sp: test_tuple_space_functions.o tuple.o tuple_space.o
	$(CC) tuple.o tuple_space.o  test_tuple_space_functions.o -o test_sp $(LDFLAGS)

# Object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Specific dependencies
tuple.o: tuple.c tuple.h tuple_encrypt.h
tuple_space.o: tuple_space.c tuple_space.h tuple.h
tuple_server.o: tuple_server.c tuple_space.h tuple_network.h tuple.h
tuple_network.o: tuple_network.c tuple_network.h tuple_space.h tuple_encrypt.h tuple.h
tuple_encrypt.o: tuple_encrypt.c tuple_encrypt.h
tuple_keygen.o: tuple_keygen.c tuple_encrypt.h
test_tuple_functions.o: tuple.c tuple.h tuple_space.c tuple_space.h
test_tuple_space_functions.o: tuple.c tuple.h tuple_space.c tuple_space.h

# Install target
install: all
    # Create installation directories with appropriate permissions
	mkdir -p $(BIN_DIR)
	mkdir -p $(SQL_DIR)
	mkdir -p $(KEY_DIR)
	chmod 755 $(BIN_DIR)
	chmod 777 $(SQL_DIR)  # Group writable for multi-user access
	chmod 777 $(KEY_DIR)  # Restrict keys to owner only
	chown $(USER):$(GROUP) $(INSTALL_DIR) $(BIN_DIR) $(SQL_DIR) $(KEY_DIR)

    # Install executables
	install -m 755 tuple_server $(BIN_DIR)/
	install -m 755 tuple_keygen $(BIN_DIR)/

    # Install SQLite database
	if [ ! -f $(SQL_DIR)/$(DB_FILE) ]; then \
        sqlite3 $(SQL_DIR)/$(DB_FILE) "CREATE TABLE IF NOT EXISTS tuples (id INTEGER PRIMARY KEY, client_id INTEGER, resource_id INTEGER, request_id INTEGER, timestamp INTEGER, state INTEGER, label TEXT, elements BLOB); PRAGMA journal_mode=WAL; VACUUM;"; \
    else \
        sqlite3 $(SQL_DIR)/$(DB_FILE) "CREATE TABLE IF NOT EXISTS tuples (id INTEGER PRIMARY KEY, client_id INTEGER, resource_id INTEGER, request_id INTEGER, timestamp INTEGER, state INTEGER, label TEXT, elements BLOB); VACUUM;"; \
    fi
	chmod 666 $(SQL_DIR)/$(DB_FILE)  # Read/write for owner and group, read for others
	chown $(USER):$(GROUP) $(SQL_DIR)/$(DB_FILE)

    # Create symbolic links in /usr/local/bin
	ln -sf $(BIN_DIR)/tuple_server /usr/local/bin/tuple_server
	ln -sf $(BIN_DIR)/tuple_keygen /usr/local/bin/tuple_keygen

clean:
	rm -f *.o $(TARGETS) $(DB_FILE)

.PHONY: all clean install
