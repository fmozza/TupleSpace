// tuple_utils.c
#include "tuple_utils.h"

Tuple *create_test_tuple(void)
{
    Tuple *t = tuple_init(1);
    if (t == NULL)
    {
        return NULL;
    }
    ElementData data;
    data.Int = 42;
    tuple_set_element(t, 0, ELEMENT_INT, data);
    t->id = 1; // Direct pointer access, pure C
    return t;
}