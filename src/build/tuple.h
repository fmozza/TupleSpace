#define _POSIX_C_SOURCE 200809L
#ifndef TUPLE_H
#define TUPLE_H
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <time.h>
#include <stdatomic.h>

typedef enum
{
    ELEMENT_INT,
    ELEMENT_FLOAT,
    ELEMENT_STRING,
    ELEMENT_TUPLE,
    ELEMENT_INT_ARRAY,
    ELEMENT_FLOAT_ARRAY,
    ELEMENT_WILDCARD
} ElementTag;

typedef struct
{
    const char *ptr;
    size_t len;
} String;

typedef struct
{
    const int64_t *ptr;
    size_t len;
} IntArray;

typedef struct
{
    const double *ptr;
    size_t len;
} FloatArray;

typedef struct Tuple Tuple;

typedef union
{
    int64_t Int;
    double Float;
    String String;
    Tuple *Tuple;
    IntArray IntArray;
    FloatArray FloatArray;
} ElementData;

typedef struct
{
    ElementTag tag;
    ElementData data;
} Element;

typedef enum
{
    STATE_NEW,
    STATE_TAKEN,
    STATE_DONE,
    STATE_RET
} TupleState;

struct Tuple
{
    uint64_t id;
    char space_id[32];
    char label[32];
    Element *elements;
    size_t elements_len;
    uint64_t client_id;
    uint64_t resource_id;
    uint64_t request_id;
    int64_t timestamp;
    TupleState state;
};

uint64_t generate_tuple_id(void);
Tuple *tuple_init(size_t elements_len);
void tuple_set_element(Tuple *self, size_t index, ElementTag tag, ElementData data);
void tuple_deinit(Tuple *self);
Tuple *tuple_copy(const Tuple *src);
int tuple_serialize(const Tuple *self, uint8_t **buffer, size_t *len);
Tuple *tuple_deserialize(uint8_t **buffer, size_t len);
void tuple_print(const Tuple *self, FILE *writer);
size_t tuple_size(const Tuple *self);

#endif