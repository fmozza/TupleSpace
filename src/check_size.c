#include <stdio.h>
#include "tuple.h"

int main()
{
    printf("ElementTag: %zu bytes\n", sizeof(ElementTag));
    printf("String: %zu bytes\n", sizeof(String));
    printf("IntArray: %zu bytes\n", sizeof(IntArray));
    printf("FloatArray: %zu bytes\n", sizeof(FloatArray));
    printf("ElementData: %zu bytes\n", sizeof(ElementData));
    printf("Element: %zu bytes\n", sizeof(Element));
    printf("TupleState: %zu bytes\n", sizeof(TupleState));
    printf("Tuple: %zu bytes\n", sizeof(Tuple));
    return 0;
}
