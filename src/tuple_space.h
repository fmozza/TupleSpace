#ifndef TUPLE_SPACE_H
#define TUPLE_SPACE_H

#define _POSIX_C_SOURCE 200809L
#include "tuple.h"
#include <stdbool.h>
#include <glib.h>
#include <pthread.h>
#include <sqlite3.h>
#include <openssl/evp.h> // Added for EVP_PKEY
#include <openssl/pem.h>

#define SPACE_ID_LEN 32

// Operation codes for tuple space commands
#define OP_PUT 0    // Put a tuple into the tuple space
#define OP_TAKE 1   // Take a tuple out (marks as taken, does not remove)
#define OP_GET 2   // Read a tuple without modifying it
#define OP_REMOVE 3 // Remove a tuple from the tuple space
#define OP_RLIST 4  // Get a list of tuples for a resource_id

typedef struct TupleSpace
{
    char space_id[SPACE_ID_LEN];
    GHashTable *entries; // uint64_t* -> Tuple*
    sqlite3 *db;
    pthread_rwlock_t rwlock;
    EVP_PKEY *server_key;
} TupleSpace;

TupleSpace *tuple_space_init(const char *server_id);
void tuple_space_deinit(TupleSpace *self);
int tuple_space_put(TupleSpace *self, Tuple *t, uint64_t *out_id);
Tuple *tuple_space_get(TupleSpace *self, uint64_t id);
bool tuple_space_remove(TupleSpace *self, uint64_t id);
Tuple *tuple_space_take(TupleSpace *self, Tuple *t);
Tuple *tuple_space_read(TupleSpace *self, Tuple *t);
Tuple *tuple_space_resource_query(TupleSpace *self, uint64_t resource_id);
bool tuple_space_update_state(TupleSpace *self, uint64_t id, TupleState state);

#endif