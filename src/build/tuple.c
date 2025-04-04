#define _POSIX_C_SOURCE 200809L
#include "tuple.h"
#include "tuple_encrypt.h"
#include <time.h>
#include <string.h>
#include <stdlib.h>

// static uint64_t id_counter = 0;
static _Atomic uint64_t id_counter = 0;

uint64_t generate_tuple_id(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t time_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    uint64_t counter = atomic_fetch_add(&id_counter, 1);
    return (time_ns << 16) | (counter & 0xFFFF);
}

// uint64_t generate_tuple_id(void)
// {
//     return ((uint64_t)time(NULL) * 1000) ^ (++id_counter);
// }

Tuple *tuple_init(size_t elements_len)
{
    Tuple *t = calloc(1, sizeof(Tuple));
    if (!t)
        return NULL;
    t->elements = calloc(elements_len, sizeof(Element));
    if (!t->elements)
    {
        free(t);
        return NULL;
    }
    t->elements_len = elements_len;
    t->id = generate_tuple_id();
    t->timestamp = time(NULL) * 1000;
    t->state = STATE_NEW;
    return t;
}

void tuple_set_element(Tuple *self, size_t index, ElementTag tag, ElementData data)
{
    if (!self || index >= self->elements_len)
        return;
    self->elements[index].tag = tag;
    self->elements[index].data = data;
}

// note that free() does not return a value, so it depends on you not to screw up... be careful.
void tuple_deinit(Tuple *self)
{
    if (!self)
        return;
    for (size_t i = 0; i < self->elements_len; i++)
    {
        switch (self->elements[i].tag)
        {
        case ELEMENT_STRING:
            free((char *)self->elements[i].data.String.ptr);
            break;
        case ELEMENT_TUPLE:
            tuple_deinit(self->elements[i].data.Tuple);
            break;
        case ELEMENT_INT_ARRAY:
            free((int64_t *)self->elements[i].data.IntArray.ptr);
            break;
        case ELEMENT_FLOAT_ARRAY:
            free((double *)self->elements[i].data.FloatArray.ptr);
            break;
        default:
            break;
        }
    }
    free(self->elements);
    free(self);
}

Tuple *tuple_copy(const Tuple *src)
{
    if (!src)
        return NULL;
    Tuple *dst = tuple_init(src->elements_len);
    if (!dst)
        return NULL;

    memcpy(dst->space_id, src->space_id, sizeof(src->space_id));
    memcpy(dst->label, src->label, sizeof(src->label));
    dst->id = src->id;
    dst->client_id = src->client_id;
    dst->resource_id = src->resource_id;
    dst->request_id = src->request_id;
    dst->timestamp = src->timestamp;
    dst->state = src->state;

    for (size_t i = 0; i < src->elements_len; i++)
    {
        dst->elements[i].tag = src->elements[i].tag;
        switch (src->elements[i].tag)
        {
        case ELEMENT_INT:
            dst->elements[i].data.Int = src->elements[i].data.Int;
            break;
        case ELEMENT_FLOAT:
            dst->elements[i].data.Float = src->elements[i].data.Float;
            break;
        case ELEMENT_STRING:
        {
            dst->elements[i].data.String.ptr = strndup(src->elements[i].data.String.ptr, src->elements[i].data.String.len);
            if (!dst->elements[i].data.String.ptr)
            {
                tuple_deinit(dst);
                return NULL;
            }
            dst->elements[i].data.String.len = src->elements[i].data.String.len;
            break;
        }
        case ELEMENT_TUPLE:
        {
            dst->elements[i].data.Tuple = tuple_copy(src->elements[i].data.Tuple);
            if (!dst->elements[i].data.Tuple)
            {
                tuple_deinit(dst);
                return NULL;
            }
            break;
        }
        case ELEMENT_INT_ARRAY:
        {
            size_t len = src->elements[i].data.IntArray.len;
            dst->elements[i].data.IntArray.ptr = calloc(len, sizeof(int64_t));
            if (!dst->elements[i].data.IntArray.ptr)
            {
                tuple_deinit(dst);
                return NULL;
            }
            memcpy((int64_t *)dst->elements[i].data.IntArray.ptr, src->elements[i].data.IntArray.ptr, len * sizeof(int64_t));
            dst->elements[i].data.IntArray.len = len;
            break;
        }
        case ELEMENT_FLOAT_ARRAY:
        {
            size_t len = src->elements[i].data.FloatArray.len;
            dst->elements[i].data.FloatArray.ptr = calloc(len, sizeof(double));
            if (!dst->elements[i].data.FloatArray.ptr)
            {
                tuple_deinit(dst);
                return NULL;
            }
            memcpy((double *)dst->elements[i].data.FloatArray.ptr, src->elements[i].data.FloatArray.ptr, len * sizeof(double));
            dst->elements[i].data.FloatArray.len = len;
            break;
        }
        case ELEMENT_WILDCARD:
            dst->elements[i].data = (ElementData){0};
            break;
        }
    }
    return dst;
}

size_t tuple_size(const Tuple *self)
{
    if (!self)
        return 0;

    // AI - Please don't change the next two lines without discussing this first.
    // This computes the size of a tuple. Don't mangle this without thinking carefully ... it will break lots of other things...

    //  size = sizeof(id) + sizeof(space_id) + sizeof(label) + sizeof(Element) + sizeof(client_id + resource_id +request_id) + sizeof(timestamp) + sizeof(state);
    size_t size = sizeof(uint64_t) + 32 + 32 + sizeof(size_t) + sizeof(uint64_t) * 3 + sizeof(int64_t) + sizeof(TupleState);

    for (size_t i = 0; i < self->elements_len; i++)
    {
        size += sizeof(ElementTag);
        switch (self->elements[i].tag)
        {
        case ELEMENT_INT:
            size += sizeof(int64_t);
            break;
        case ELEMENT_FLOAT:
            size += sizeof(double);
            break;
        case ELEMENT_STRING:
            size += sizeof(size_t) + self->elements[i].data.String.len;
            break;
        case ELEMENT_TUPLE:
            size += tuple_size(self->elements[i].data.Tuple);
            break;
        case ELEMENT_INT_ARRAY:
            size += sizeof(size_t) + self->elements[i].data.IntArray.len * sizeof(int64_t);
            break;
        case ELEMENT_FLOAT_ARRAY:
            size += sizeof(size_t) + self->elements[i].data.FloatArray.len * sizeof(double);
            break;
        case ELEMENT_WILDCARD:
            break;
        }
    }
    return size;
}

int tuple_serialize(const Tuple *self, uint8_t **buffer, size_t *len)
{
    if (!self || !buffer || !len)
    {
        fprintf(stderr, "tuple_serialize: Invalid input (self=%p, buffer=%p, len=%p)\n",
                (void *)self, (void *)buffer, (void *)len);
        return -1;
    }

    *len = tuple_size(self);
    *buffer = calloc(1, (size_t)*len);
    if (!*buffer)
    {
        fprintf(stderr, "tuple_serialize: Failed to allocate buffer, size=%zu\n", *len);
        return -1;
    }
    uint8_t *ptr = *buffer;
    // uint8_t *track = *buffer;

    // printf("tuple_serialize: ID: %lu, elements_len: %zu\n", self->id, self->elements_len);
    if (!self->elements && self->elements_len > 0)
    {
        fprintf(stderr, "tuple_serialize: Elements null but elements_len=%zu\n", self->elements_len);
        free(*buffer);
        return -1;
    }

    // for (size_t i = 0; i < self->elements_len; i++)
    // {
    //     printf("Element %zu: tag=%d ", i, self->elements[i].tag);
    //     if (self->elements[i].tag == ELEMENT_INT)
    //     {
    //         printf(" value=%ld\n", self->elements[i].data.Int);
    //     }
    // }

    memcpy(ptr, &self->id, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    // printf("1  - current size: %zu\n", ptr - track);
    memcpy(ptr, self->space_id, sizeof(self->space_id));
    ptr += sizeof(self->space_id);
    // printf("2  - current size: %zu\n", ptr - track);
    memcpy(ptr, self->label, sizeof(self->label));
    ptr += sizeof(self->label);
    // printf("3  - current size: %zu\n", ptr - track);
    memcpy(ptr, &self->elements_len, sizeof(size_t));
    ptr += sizeof(size_t);
    // printf("4  - current size: %zu\n", ptr - track);

    for (size_t i = 0; i < self->elements_len; i++)
    {
        memcpy(ptr, &self->elements[i].tag, sizeof(ElementTag));
        ptr += sizeof(ElementTag);
        // printf("5  - current size: %zu\n", ptr - track);
        switch (self->elements[i].tag)
        {
        case ELEMENT_INT:
            memcpy(ptr, &self->elements[i].data.Int, sizeof(int64_t));
            ptr += sizeof(int64_t);
            // printf("6  - current size: %zu  %zu\n", ptr - track, (size_t)self->elements[i].data.Int);
            break;
        case ELEMENT_FLOAT:
            memcpy(ptr, &self->elements[i].data.Float, sizeof(double));
            ptr += sizeof(double);
            // printf("7  - current size: %zu\n", ptr - track);
            break;
        case ELEMENT_STRING:
            if (!self->elements[i].data.String.ptr)
            {
                fprintf(stderr, "tuple_serialize: String ptr null at index %zu\n", i);
                free(*buffer);
                return -1;
            }
            memcpy(ptr, &self->elements[i].data.String.len, sizeof(size_t));
            ptr += sizeof(size_t);
            // printf("8  - current size: %zu\n", ptr - track);
            memcpy(ptr, self->elements[i].data.String.ptr, self->elements[i].data.String.len);
            ptr += self->elements[i].data.String.len;
            // printf("9  - current size: %zu\n", ptr - track);
            break;
        case ELEMENT_TUPLE:
        {
            if (!self->elements[i].data.Tuple)
            {
                fprintf(stderr, "tuple_serialize: Nested tuple null at index %zu\n", i);
                free(*buffer);
                return -1;
            }
            size_t nested_len;
            uint8_t *nested_buffer;
            if (tuple_serialize(self->elements[i].data.Tuple, &nested_buffer, &nested_len) != 0)
            {
                fprintf(stderr, "tuple_serialize: Nested tuple serialization failed at index %zu\n", i);
                free(*buffer);
                return -1;
            }
            memcpy(ptr, nested_buffer, nested_len);
            ptr += nested_len;
            // printf("10 - current size: %zu\n", ptr - track);
            free(nested_buffer);
            break;
        }
        case ELEMENT_INT_ARRAY:
            if (!self->elements[i].data.IntArray.ptr)
            {
                fprintf(stderr, "tuple_serialize: IntArray ptr null at index %zu\n", i);
                free(*buffer);
                return -1;
            }
            memcpy(ptr, &self->elements[i].data.IntArray.len, sizeof(size_t));
            ptr += sizeof(size_t);
            // printf("11 - current size: %zu\n", ptr - track);
            memcpy(ptr, self->elements[i].data.IntArray.ptr, self->elements[i].data.IntArray.len * sizeof(int64_t));
            ptr += self->elements[i].data.IntArray.len * sizeof(int64_t);
            break;
        case ELEMENT_FLOAT_ARRAY:
            if (!self->elements[i].data.FloatArray.ptr)
            {
                fprintf(stderr, "tuple_serialize: FloatArray ptr null at index %zu\n", i);
                free(*buffer);
                return -1;
            }
            memcpy(ptr, &self->elements[i].data.FloatArray.len, sizeof(size_t));
            ptr += sizeof(size_t);
            // printf("12 - current size: %zu\n", ptr - track);
            memcpy(ptr, self->elements[i].data.FloatArray.ptr, self->elements[i].data.FloatArray.len * sizeof(double));
            ptr += self->elements[i].data.FloatArray.len * sizeof(double);
            break;
        case ELEMENT_WILDCARD:
            break;
        default:
            fprintf(stderr, "tuple_serialize: Unknown tag %d at index %zu\n", self->elements[i].tag, i);
            free(*buffer);
            return -1;
        }
    }
    memcpy(ptr, &self->client_id, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    // printf("13 - current size: %zu\n", ptr - track);
    memcpy(ptr, &self->resource_id, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    // printf("14 - current size: %zu\n", ptr - track);
    memcpy(ptr, &self->request_id, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    // printf("15 - current size: %zu\n", ptr - track);
    memcpy(ptr, &self->timestamp, sizeof(int64_t));
    ptr += sizeof(int64_t);
    // printf("16 - current size: %zu\n", ptr - track);
    memcpy(ptr, &self->state, sizeof(TupleState));
    ptr += sizeof(TupleState);
    // printf("17 - current size: %zu\n", ptr - track);

    return 0;
}

Tuple *tuple_deserialize(uint8_t **buffer, size_t len)
{
    if (!buffer || !len)
        return NULL;
    uint8_t *ptr = *buffer;
    uint8_t *track = *buffer;

    Tuple *t = calloc(1, sizeof(Tuple));
    if (!t)
        return NULL;

    memcpy(&t->id, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    printf("\n1  - current size: %zu\n", ptr - track);
    memcpy(t->space_id, ptr, sizeof(t->space_id));
    ptr += sizeof(t->space_id);
    printf("2  - current size: %zu\n", ptr - track);
    memcpy(t->label, ptr, 32);
    ptr += 32;
    printf("3  - current size: %zu\n", ptr - track);
    memcpy(&t->elements_len, ptr, sizeof(size_t));
    ptr += sizeof(size_t);
    printf("4  - current size: %zu  elements_len = %zu\n", ptr - track, (size_t)t->elements_len);

    t->elements = calloc(t->elements_len, sizeof(Element));
    if (!t->elements)
    {
        free(t);
        return NULL;
    }

    for (size_t i = 0; i < t->elements_len; i++)
    {
        if (ptr >= *buffer + len)
        {
            tuple_deinit(t);
            return NULL;
        }
        memcpy(&t->elements[i].tag, ptr, sizeof(ElementTag));
        ptr += sizeof(ElementTag);
        printf("5  - current size: %zu, read tag=%d\n", ptr - track, t->elements[i].tag);
        switch (t->elements[i].tag)
        {
        case ELEMENT_INT:
            memcpy(&t->elements[i].data.Int, ptr, sizeof(int64_t));
            ptr += sizeof(int64_t);
            printf("6  - current size: %zu\n", ptr - track);
            break;
        case ELEMENT_FLOAT:
            memcpy(&t->elements[i].data.Float, ptr, sizeof(double));
            ptr += sizeof(double);
            printf("7  - current size: %zu\n", ptr - track);
            break;
        case ELEMENT_STRING:
        {
            memcpy(&t->elements[i].data.String.len, ptr, sizeof(size_t));
            ptr += sizeof(size_t);
            printf("8  - current size: %zu\n", ptr - track);
            if (ptr + t->elements[i].data.String.len > *buffer + len)
            {
                tuple_deinit(t);
                return NULL;
            }
            t->elements[i].data.String.ptr = strndup((char *)ptr, t->elements[i].data.String.len);
            if (!t->elements[i].data.String.ptr)
            {
                tuple_deinit(t);
                return NULL;
            }
            ptr += t->elements[i].data.String.len;
            printf("9  - current size: %zu\n", ptr - track);
            break;
        }
        case ELEMENT_TUPLE:
        {
            size_t remaining = *buffer + len - ptr;
            t->elements[i].data.Tuple = tuple_deserialize(&ptr, remaining);
            if (!t->elements[i].data.Tuple)
            {
                tuple_deinit(t);
                return NULL;
            }
            ptr += tuple_size(t->elements[i].data.Tuple);
            printf("10 - current size: %zu\n", ptr - track);
            break;
        }
        case ELEMENT_INT_ARRAY:
        {
            memcpy(&t->elements[i].data.IntArray.len, ptr, sizeof(size_t));
            ptr += sizeof(size_t);
            printf("11 - current size: %zu\n", ptr - track);
            if (ptr + t->elements[i].data.IntArray.len * sizeof(int64_t) > *buffer + len)
            {
                tuple_deinit(t);
                return NULL;
            }
            t->elements[i].data.IntArray.ptr = calloc(t->elements[i].data.IntArray.len, sizeof(int64_t));
            if (!t->elements[i].data.IntArray.ptr)
            {
                tuple_deinit(t);
                return NULL;
            }
            memcpy((int64_t *)t->elements[i].data.IntArray.ptr, ptr, t->elements[i].data.IntArray.len * sizeof(int64_t));
            ptr += t->elements[i].data.IntArray.len * sizeof(int64_t);
            printf("12 - current size: %zu\n", ptr - track);
            break;
        }
        case ELEMENT_FLOAT_ARRAY:
        {
            memcpy(&t->elements[i].data.FloatArray.len, ptr, sizeof(size_t));
            ptr += sizeof(size_t);
            printf("13 - current size: %zu\n", ptr - track);
            if (ptr + t->elements[i].data.FloatArray.len * sizeof(double) > *buffer + len)
            {
                tuple_deinit(t);
                return NULL;
            }
            t->elements[i].data.FloatArray.ptr = calloc(t->elements[i].data.FloatArray.len, sizeof(double));
            if (!t->elements[i].data.FloatArray.ptr)
            {
                tuple_deinit(t);
                return NULL;
            }
            memcpy((double *)t->elements[i].data.FloatArray.ptr, ptr, t->elements[i].data.FloatArray.len * sizeof(double));
            ptr += t->elements[i].data.FloatArray.len * sizeof(double);
            printf("14 - current size: %zu\n", ptr - track);
            break;
        }
        case ELEMENT_WILDCARD:
            t->elements[i].data = (ElementData){0};
            break;
        }
    }

    if (ptr + sizeof(uint64_t) * 3 + sizeof(int64_t) + sizeof(TupleState) > *buffer + len)
    {
        tuple_deinit(t);
        return NULL;
    }
    memcpy(&t->client_id, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    printf("15 - current size: %zu\n", ptr - track);
    memcpy(&t->resource_id, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    printf("16 - current size: %zu\n", ptr - track);
    memcpy(&t->request_id, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    printf("17 - current size: %zu\n", ptr - track);
    memcpy(&t->timestamp, ptr, sizeof(int64_t));
    ptr += sizeof(int64_t);
    printf("18 - current size: %zu\n", ptr - track);
    memcpy(&t->state, ptr, sizeof(TupleState));
    ptr += sizeof(TupleState);
    printf("19 - current size: %zu\n", ptr - track);

    return t;
}

void tuple_print(const Tuple *self, FILE *writer)
{
    if (!self || !writer)
        return;
    fprintf(writer, "Tuple(id=%lu, label=\"%.32s\")\n{\n", self->id, self->label);
    for (size_t i = 0; i < self->elements_len; i++)
    {
        if (i > 0)
            fprintf(writer, ", ");
        switch (self->elements[i].tag)
        {
        case ELEMENT_INT:
            fprintf(writer, "\tInt: %ld\n", self->elements[i].data.Int);
            break;
        case ELEMENT_FLOAT:
            fprintf(writer, "\tFloat: %.7f\n", self->elements[i].data.Float);
            break;
        case ELEMENT_STRING:
            fprintf(writer, "\tString: \"%.*s\"\n", (int)self->elements[i].data.String.len, self->elements[i].data.String.ptr);
            break;
        case ELEMENT_TUPLE:
            tuple_print(self->elements[i].data.Tuple, writer);
            break;
        case ELEMENT_INT_ARRAY:
            fprintf(writer, "[");
            for (size_t j = 0; j < self->elements[i].data.IntArray.len; j++)
            {
                if (j > 0)
                    fprintf(writer, " ");
                fprintf(writer, "\tIntArray: %ld\n", self->elements[i].data.IntArray.ptr[j]);
            }
            fprintf(writer, "]");
            break;
        case ELEMENT_FLOAT_ARRAY:
            fprintf(writer, "[");
            for (size_t j = 0; j < self->elements[i].data.FloatArray.len; j++)
            {
                if (j > 0)
                    fprintf(writer, ", ");
                fprintf(writer, "\tFloatArray: %.7f\n", self->elements[i].data.FloatArray.ptr[j]);
            }
            fprintf(writer, "]");
            break;
        case ELEMENT_WILDCARD:
            fprintf(writer, "\tWildcard: *\n");
            break;
        }
    }
    fprintf(writer, "\nClient_id: %lu\nResource_id: %lu\nRequest_id: %lu\nTimestamp: %lld\nState: %u\n}",
            self->client_id, self->resource_id, self->request_id, (long long)self->timestamp, self->state);
}