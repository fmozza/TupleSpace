#define _POSIX_C_SOURCE 200809L
#include "tuple_space.h"
#include <string.h>
#include <stdlib.h>

TupleSpace *tuple_space_init(const char *server_id)
{
    TupleSpace *self = calloc(1, sizeof(TupleSpace));
    if (!self)
    {
        return NULL;
    }

    const char *input = "reimann 01";
    strncpy(self->space_id, input, sizeof(self->space_id));
    size_t input_len = strlen(input);
    if (input_len < sizeof(self->space_id))
    {
        memset(self->space_id + input_len, ' ', sizeof(self->space_id) - input_len);
    }

    // create hash table for tuple space entries.

    self->entries = g_hash_table_new(g_int64_hash, g_int64_equal);
    if (!self->entries)
    {
        fprintf(stderr, "g_hash_table_new failed\n");
        goto error;
    }

    // Initialize SQLlite database, tables and indices.
    const char *db_path = "/usr/local/tuple_space/sql/tuple_space.db";
    if (sqlite3_open(db_path, &self->db) != SQLITE_OK)
    {
        fprintf(stderr, "sqlite3_open failed for %s: %s\n", db_path, sqlite3_errmsg(self->db));
        goto error;
    }

    // Check read-only status
    if (sqlite3_db_readonly(self->db, "main") == 1)
    {
        fprintf(stderr, "Database %s opened in read-only mode\n", db_path);
        goto error;
    }

    // Set journal mode
    if (sqlite3_exec(self->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "PRAGMA journal_mode=WAL failed: %s\n", sqlite3_errmsg(self->db));
        goto error;
    }

    // Drop existing table if it exists
    char drop_sql[] = "DROP TABLE IF EXISTS tuples";
    if (sqlite3_exec(self->db, drop_sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to drop existing table: %s\n", sqlite3_errmsg(self->db));
        goto error;
    }

    // Create new table
    char create_sql[] = "CREATE TABLE tuples ("
                        "id INTEGER PRIMARY KEY, "
                        "client_id INTEGER, "
                        "resource_id INTEGER, "
                        "request_id INTEGER, "
                        "timestamp INTEGER, "
                        "state INTEGER, "
                        "label TEXT, "
                        "elements BLOB)";
    if (sqlite3_exec(self->db, create_sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to create table: %s\n", sqlite3_errmsg(self->db));
        goto error;
    }

    // Create indices
    char index1_sql[] = "CREATE INDEX IF NOT EXISTS idx_client_id ON tuples(client_id)";
    char index2_sql[] = "CREATE INDEX IF NOT EXISTS idx_timestamp ON tuples(timestamp)";

    if (sqlite3_exec(self->db, index1_sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to create client_id index: %s\n", sqlite3_errmsg(self->db));
        goto error;
    }

    if (sqlite3_exec(self->db, index2_sql, NULL, NULL, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to create timestamp index: %s\n", sqlite3_errmsg(self->db));
        goto error;
    }

    // Finished initializing new table

    char key_path[256];
    snprintf(key_path, sizeof(key_path), "/usr/local/tuple_space/.keys/server_%s_key.pem", server_id);
    FILE *f = fopen(key_path, "r");
    if (!f)
    {
        printf("Can't open key path ...\n");
        goto error;
    }
    self->server_key = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!self->server_key)
        goto error;

    pthread_rwlock_init(&self->rwlock, NULL);
    return self;

error:
    tuple_space_deinit(self);
    return NULL;
}

void tuple_space_deinit(TupleSpace *self)
{
    if (!self)
        return;
    if (self->entries)
    {
        GHashTableIter iter;
        gpointer key, tuple;
        g_hash_table_iter_init(&iter, self->entries);
        while (g_hash_table_iter_next(&iter, &key, &tuple))
        {
            tuple_deinit(tuple);
        }
        g_hash_table_destroy(self->entries);
        // free(key);
    }
    if (self->db)
        sqlite3_close(self->db);
    if (self->server_key)
        EVP_PKEY_free(self->server_key);
    pthread_rwlock_destroy(&self->rwlock);
    free(self);
}

int tuple_space_put(TupleSpace *self, Tuple *t, uint64_t *out_id)
{
    pthread_rwlock_wrlock(&self->rwlock);
    if (g_hash_table_insert(self->entries, (gpointer)&t->id, (gpointer)t) == false)
    {
        fprintf(stderr, "tuple_space_put: hash_table_insert failed.\n");
        return -1;
    }
    if (out_id) // Return the assigned ID
    {
        *out_id = t->id;
    }

    uint8_t *blob;
    size_t blob_len = 0;
    if (tuple_serialize(t, &blob, &blob_len) != 0)
    {
        return -1;
    }

    sqlite3_stmt *stmt;
    const char *sql = "INSERT OR REPLACE INTO tuples (id, client_id, resource_id, request_id, "
                      "timestamp, state, label, elements) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    if (sqlite3_prepare_v2(self->db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        free(blob);
        pthread_rwlock_unlock(&self->rwlock);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, t->id);
    sqlite3_bind_int64(stmt, 2, t->client_id);
    sqlite3_bind_int64(stmt, 3, t->resource_id);
    sqlite3_bind_int64(stmt, 4, t->request_id);
    sqlite3_bind_int64(stmt, 5, t->timestamp);
    sqlite3_bind_int(stmt, 6, t->state);
    sqlite3_bind_text(stmt, 7, (const char *)t->label, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 8, blob, blob_len, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
    {
        free(blob);
        pthread_rwlock_unlock(&self->rwlock);
        return -1;
    }
    pthread_rwlock_unlock(&self->rwlock);
    free(blob);
    return 0;
}

Tuple *tuple_space_get(TupleSpace *self, uint64_t id)
{
    pthread_rwlock_rdlock(&self->rwlock);
    Tuple *t = g_hash_table_lookup(self->entries, &id);
    Tuple *copy = t ? tuple_copy(t) : NULL;
    pthread_rwlock_unlock(&self->rwlock);
    return copy;
}

bool tuple_space_remove(TupleSpace *self, uint64_t id)
{
    pthread_rwlock_wrlock(&self->rwlock);
    gboolean valid = g_hash_table_remove(self->entries, &id);
    if (!valid)
    {
        printf("id = %zu  has not been removed.\n", id);
        return false;
    }

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(self->db, "DELETE FROM tuples WHERE id = ?", -1, &stmt, 0) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE)
    {
        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&self->rwlock);
        return false;
    }
    sqlite3_finalize(stmt);

    g_hash_table_remove(self->entries, &id);
    pthread_rwlock_unlock(&self->rwlock);
    return true;
}

Tuple *tuple_space_take(TupleSpace *self, Tuple *req)
{
    pthread_rwlock_wrlock(&self->rwlock);
    Tuple *t = tuple_space_get(self, req->id);
    if (!t)
    {
        printf("tuple_space_take: No tuple found for ID: %lu\n", req->id);
        pthread_rwlock_unlock(&self->rwlock);
        return NULL;
    }
    printf("tuple_space_take: Found tuple ID: %lu, label: %s, elements_len: %zu\n",
           t->id, t->label, t->elements_len);
    printf("\n---------------------\nTuple t\n");
    tuple_print(t, stdout);
    printf("\n---------------------\n");
    for (size_t i = 0; i < t->elements_len; i++)
    {
        if (t->elements[i].tag == ELEMENT_INT)
        {
            printf("  Element %zu: tag=%d, value=%ld\n", i, t->elements[i].tag, t->elements[i].data.Int);
        }
        else
        {
            printf("  Element %zu: tag=%d\n", i, t->elements[i].tag);
        }
    }
    Tuple *res = tuple_copy(t);
    if (!res)
    {
        printf("tuple_space_take: tuple_copy failed for ID: %lu\n", t->id);
        tuple_deinit(t);
        pthread_rwlock_unlock(&self->rwlock);
        return NULL;
    }
    res->timestamp = time(NULL) * 1000;
    printf("tuple_space_take: Copied tuple ID: %lu, elements_len: %zu\n", res->id, res->elements_len);
    for (size_t i = 0; i < res->elements_len; i++)
    {
        if (res->elements[i].tag == ELEMENT_INT)
        {
            printf("  Copied element %zu: tag=%d, value=%ld\n", i, res->elements[i].tag, res->elements[i].data.Int);
        }
        else
        {
            printf("  Copied element %zu: tag=%d\n", i, res->elements[i].tag);
        }
    }
    res->state = STATE_TAKEN;
    printf("res->state = %d\n", res->state);
    uint64_t id_key = t->id;
    if (g_hash_table_remove(self->entries, &id_key) == false)
    {
        fprintf(stderr, "tuple_space_take: Failed to remove ID %lu from entries\n", t->id);
    }

    sqlite3_stmt *stmt;
    const char *sql = "DELETE FROM tuples WHERE id = ?";
    if (sqlite3_prepare_v2(self->db, sql, -1, &stmt, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int64(stmt, 1, t->id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    else
    {
        printf("tuple_space_take: SQL DELETE failed for ID: %lu\n", t->id);
    }
    pthread_rwlock_unlock(&self->rwlock);
    printf("\n---------------------\nTuple res again\n");
    tuple_print(res, stdout);
    printf("\n---------------------\n");
    printf("res->state = %d\n", res->state);
    return res;
}

Tuple *tuple_space_read(TupleSpace *self, Tuple *pattern)
{
    pthread_rwlock_rdlock(&self->rwlock);
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init(&iter, self->entries);
    while (g_hash_table_iter_next(&iter, &key, &value))
    {
        Tuple *t = (Tuple *)value;
        if ((!pattern->resource_id || pattern->resource_id == t->resource_id) &&
            (!pattern->client_id || pattern->client_id == t->client_id))
        {
            Tuple *copy = tuple_copy(t);
            pthread_rwlock_unlock(&self->rwlock);
            return copy;
        }
    }
    pthread_rwlock_unlock(&self->rwlock);
    return NULL;
}

Tuple *tuple_space_resource_query(TupleSpace *self, uint64_t resource_id)
{
    pthread_rwlock_rdlock(&self->rwlock);
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id FROM tuples WHERE resource_id = ? AND state = ?";
    if (sqlite3_prepare_v2(self->db, sql, -1, &stmt, 0) != SQLITE_OK)
        goto error;
    sqlite3_bind_int64(stmt, 1, resource_id);
    sqlite3_bind_int(stmt, 2, STATE_NEW);

    GArray *ids = g_array_new(FALSE, FALSE, sizeof(int64_t));
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        int64_t id = sqlite3_column_int64(stmt, 0);
        g_array_append_val(ids, id);
    }
    sqlite3_finalize(stmt);

    if (!ids->len)
    {
        g_array_free(ids, TRUE);
        goto error;
    }

    Element e = {.tag = ELEMENT_INT_ARRAY, .data.IntArray = {.ptr = (int64_t *)ids->data, .len = ids->len}};
    Tuple *t = tuple_init(1);
    if (!t)
    {
        g_array_free(ids, TRUE);
        goto error;
    }
    tuple_set_element(t, 0, ELEMENT_INT_ARRAY, e.data);
    t->resource_id = resource_id;
    t->state = STATE_NEW;
    strncpy(t->label, "resource query", 32);

    pthread_rwlock_unlock(&self->rwlock);
    return t;

error:
    pthread_rwlock_unlock(&self->rwlock);
    return NULL;
}

bool tuple_space_update_state(TupleSpace *self, uint64_t id, TupleState state)
{
    pthread_rwlock_wrlock(&self->rwlock);
    Tuple *t = g_hash_table_lookup(self->entries, &id);
    if (!t || t->state >= state)
    {
        pthread_rwlock_unlock(&self->rwlock);
        return false;
    }

    sqlite3_stmt *stmt;
    const char *sql = "UPDATE tuples SET state = ? WHERE id = ?";
    if (sqlite3_prepare_v2(self->db, sql, -1, &stmt, 0) != SQLITE_OK ||
        sqlite3_bind_int(stmt, 1, state) != SQLITE_OK ||
        sqlite3_bind_int64(stmt, 2, id) != SQLITE_OK ||
        sqlite3_step(stmt) != SQLITE_DONE)
    {
        sqlite3_finalize(stmt);
        pthread_rwlock_unlock(&self->rwlock);
        return false;
    }
    sqlite3_finalize(stmt);
    t->state = state;
    pthread_rwlock_unlock(&self->rwlock);
    return true;
}