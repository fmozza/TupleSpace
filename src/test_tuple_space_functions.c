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

static int seeded = 0;

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

Tuple *generate_tuple()
{
    if (!seeded)
    {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    int64_t len = (int64_t)((rand() % 4) + 2);
    Tuple *t0 = tuple_init(len);
    if (t0 == NULL)
    {
        fprintf(stderr, "generate_tuple: tuple_init failed.");
        return NULL;
    }
    for (int i = 0; i < len; i++)
    {
        uint8_t elem = (uint8_t)((rand() % 5));
        switch (elem)
        {
        case ELEMENT_INT:
            t0->elements[i].tag = ELEMENT_INT;
            t0->elements[i].data.Int = (int64_t)42;
            break;
        case ELEMENT_FLOAT:
            t0->elements[i].tag = ELEMENT_FLOAT;
            t0->elements[i].data.Float = (double)3.1415926;
            break;
        case ELEMENT_STRING:
            char *test_str = strdup("This is a test");
            t0->elements[i].tag = ELEMENT_STRING;
            t0->elements[i].data.String.ptr = test_str;
            t0->elements[i].data.String.len = strlen(test_str);
            break;
        case ELEMENT_TUPLE:
            struct Tuple *nested = tuple_init(1);
            nested->elements[0].tag = ELEMENT_INT;
            nested->elements[0].data.Int = (int64_t)43;
            t0->elements[i].tag = ELEMENT_TUPLE;
            t0->elements[i].data.Tuple = nested;
            break;
        case ELEMENT_BLOB:
            char *blob_data = strdup("This is a blob");
            t0->elements[i].tag = ELEMENT_BLOB;
            t0->elements[i].data.Blob.ptr = blob_data;
            t0->elements[i].data.Blob.size = strlen(blob_data);
            break;
        case ELEMENT_INT_ARRAY:
            int *int_array = (int *)generate_random_ints(3, 100);
            t0->elements[i].tag = ELEMENT_INT_ARRAY;
            t0->elements[i].data.IntArray.ptr = (int64_t *)int_array;
            t0->elements[i].data.IntArray.len = 3;
            break;
        case ELEMENT_FLOAT_ARRAY:
            double *float_array = (double *)generate_random_doubles(3);
            t0->elements[i].tag = ELEMENT_FLOAT_ARRAY;
            t0->elements[i].data.FloatArray.ptr = (double *)float_array;
            t0->elements[i].data.FloatArray.len = 3;
            break;
        case ELEMENT_STRING_ARRAY:
            char *str_array[3] = {"String 1", "String 2", "String 3"};
            t0->elements[i].tag = ELEMENT_STRING_ARRAY;
            t0->elements[i].data.StringArray.ptr = (String *)malloc(3 * sizeof(String));
            for (int j = 0; j < 3; j++)
            {
                t0->elements[i].data.StringArray.ptr[j].ptr = strdup(str_array[j]);
                t0->elements[i].data.StringArray.ptr[j].len = strlen(str_array[j]);
            }
            t0->elements[i].data.StringArray.len = 3;
            break;
        case ELEMENT_TUPLE_ARRAY:
            t0->elements[i].tag = ELEMENT_TUPLE_ARRAY;
            t0->elements[i].data.TupleArray.ptr = (Tuple *)malloc(3 * sizeof(Tuple));
            for (int j = 0; j < 3; j++)
            {
                t0->elements[i].data.TupleArray.ptr[j] = *tuple_init(1);
                t0->elements[i].data.TupleArray.ptr[j].elements[0].tag = ELEMENT_INT;
                t0->elements[i].data.TupleArray.ptr[j].elements[0].data.Int = (int64_t)44 + j;
            }
            t0->elements[i].data.TupleArray.len = 3;
            break;
        case ELEMENT_BLOB_ARRAY:
            t0->elements[i].tag = ELEMENT_BLOB_ARRAY;
            t0->elements[i].data.BlobArray.ptr = (Blob *)malloc(3 * sizeof(Blob));
            for (int j = 0; j < 3; j++)
            {
                t0->elements[i].data.BlobArray.ptr[j].ptr = strdup("This is a blob array");
                t0->elements[i].data.BlobArray.ptr[j].size = strlen("This is a blob array");
            }
            t0->elements[i].data.BlobArray.len = 3;
            break;
        }
    }
    return t0;
}

int main()
{
    // -- tuple_space testing

    pline();
    printf("TupleSpace initialize:  tuple_space_init(server_id)\n");
    const char *server_id = strdup("01");
    TupleSpace *space = tuple_space_init(server_id);

    if (!space)
    {
        perror("tuple_space_init failed ... ");
        return 1;
    }
    pline();
    // printf("tuple space init succeeded: %s \n", space->space_id);

    // ------------------------------------------------------------------------------

    Tuple *t0 = NULL;
    uint64_t new_id = 0;
    for (int i = 0; i < 50000; i++)
    {
        t0 = generate_tuple(space);
        new_id = t0->id;
        if (tuple_space_put(space, t0, &new_id) != 0)
        {
            tuple_deinit(t0);
            fprintf(stderr, "tuple_space_put failed\n");
            return -1;
        }
    }

    pline();
    uint64_t test_id = 0;
    // printf("TupleSpace resource query:  tuple_space_resource_query(space, test_id); \n");
    Tuple *t3 = tuple_space_resource_query(space, test_id);
    if (t3 == NULL)
    {
        fprintf(stderr, "QUERY operation failed.");
        tuple_deinit(t3);
    }

    int64_t remove_id;
    int nquery = t3->elements[0].data.IntArray.len;
    printf("Number of elements to remove: %d\n", nquery);
    for (int i = 0; i < nquery; i++)
    {
        remove_id = (int64_t)t3->elements[0].data.IntArray.ptr[i];
        if (!tuple_space_remove(space, remove_id))
        {
            fprintf(stdout, " * \n");
        }
    }

    pline();
    printf("\nTupleSpace deinit:  tuple_space_deinit(space); \n");
    tuple_space_deinit(space);
    printf("Tests completed.\n");
    return 0;
}
