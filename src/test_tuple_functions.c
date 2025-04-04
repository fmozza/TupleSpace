// test_tuple.c
// test tuple functions.

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <glib.h>
#include <time.h>
#include <limits.h>
#include "tuple.h"
#include "tuple_space.h"

void pline()
{
    printf("\n\n---------------------------------------------  ");
}

int64_t *generate_random_ints(int n, int m)
{
    if (m < 1 || m > INT_MAX)
    {
        printf("Error: m must be between 1 and %d.\n", INT_MAX);
        return NULL;
    }
    static int seeded = 0;
    if (!seeded)
    {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    int64_t *random_numbers = (int64_t *)malloc(n * sizeof(int64_t));
    if (!random_numbers)
    {
        printf("Error: Memory allocation failed.\n");
        return NULL;
    }

    for (int i = 0; i < n; i++)
    {
        random_numbers[i] = (int64_t)((rand() % m) + 1); // Generate number between 0 and m
    }

    return random_numbers;
}

// Function to generate n random doubles between 0.0 and 1.0
double *generate_random_doubles(size_t n)
{
    // Seed the random number generator once
    static int seeded = 0;
    if (!seeded)
    {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    // Allocate memory for n doubles
    double *result = (double *)malloc(n * sizeof(double));
    if (result == NULL)
    {
        return NULL; // Memory allocation failed
    }

    // Generate random doubles
    for (size_t i = 0; i < n; i++)
    {
        result[i] = (double)rand() / RAND_MAX;
    }

    return result;
}

int main()
{
    size_t element_len = 6;
    Tuple *t;

    // void tuple_set_element(Tuple *self, size_t index, ElementTag tag, ElementData data)
    pline();
    t = tuple_init(element_len); // Assume this allocates a Tuple with elements_len = 3

    // Integer
    t->elements[0].tag = ELEMENT_INT;
    t->elements[0].data.Int = 42;

    // // Float
    // t->elements[1].tag = ELEMENT_FLOAT;
    // t->elements[1].data.Float = 3.1415926;

    // // String
    // char *hello_str = strdup("Hello, World!");
    // t->elements[2].tag = ELEMENT_STRING;
    // t->elements[2].data.String.ptr = hello_str;
    // t->elements[2].data.String.len = strlen(hello_str);

    // // Nested Tuple
    // struct Tuple *nested = tuple_init(1);
    // nested->elements[0].tag = ELEMENT_INT;
    // nested->elements[0].data.Int = 100;
    // t->elements[3].tag = ELEMENT_TUPLE;
    // t->elements[3].data.Tuple = nested;

    // // Integer Array
    // int n = 100;
    // int m = 5;
    // int *int_array = (int *)generate_random_ints(n, m);
    // t->elements[4].tag = ELEMENT_INT_ARRAY;
    // t->elements[4].data.IntArray.ptr = (int64_t *)int_array;
    // t->elements[4].data.IntArray.len = n;

    // // Float Array
    // double *random_doubles = (double *)generate_random_doubles(10);
    // t->elements[5].tag = ELEMENT_FLOAT_ARRAY;
    // t->elements[5].data.FloatArray.ptr = random_doubles;
    // t->elements[5].data.FloatArray.len = 10;

    printf(": size of t: %zu\n", tuple_size(t));
    tuple_print(t, stdout);

    // pline();
    // printf("test: tuple_copy ");
    // Tuple *copy = tuple_copy(t);
    // printf("size of the copy: %zu\n", tuple_size(copy));
    // tuple_print(copy, stdout);

    // pline();
    // printf("test: tuple_deinit(t)\n");
    // tuple_deinit(t);

    pline();
    printf("test: tuple_serialize");
    printf(": size of copy: %zu\n", tuple_size(t));
    uint8_t *blob;
    size_t blob_len;
    if (tuple_serialize(t, &blob, &blob_len) != 0)
    {
        printf("tuple_serialize failed ...");
        tuple_deinit(t);
        return 1;
    }

    // pline();
    // printf("test: tuple_deserialize blob_len = %zu", (size_t)blob_len);
    // Tuple *t0 = tuple_deserialize(&blob, (size_t)blob_len);
    // if (t0 == NULL)
    // {
    //     printf("tuple_deserialize failed ...");
    //     tuple_deinit(t0);
    //     return 1;
    // }
    // printf("size of t0: %zu  %zu\n", sizeof(t0), sizeof(blob) * blob_len);
    // tuple_print(t0, stdout);

    // printf("\n\nDone all tests.\n");
    return 0;
}