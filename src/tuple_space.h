#ifndef TUPLE_SPACE_H
#define TUPLE_SPACE_H

#include <stdint.h>

typedef struct TupleSpace TupleSpace;

TupleSpace *tuplespace_create(void);
void tuplespace_destroy(TupleSpace *ts);
int tuplespace_put_int(TupleSpace *ts, int64_t value);
int tuplespace_get_int(TupleSpace *ts, int64_t value);
int tuplespace_take_int(TupleSpace *ts, int64_t value, int64_t *out_value);
int tuplespace_save(TupleSpace *ts, const char *path);
int tuplespace_put_string(TupleSpace *ts, const char *ptr, size_t len);
int tuplespace_take_string(TupleSpace *ts, const char *ptr, size_t len, char **out_ptr, size_t *out_len);

#endif