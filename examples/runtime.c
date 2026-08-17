#include <stddef.h>

void *memcpy(void *destination, const void *source, size_t length) {
    unsigned char *output = (unsigned char *)destination;
    const unsigned char *input = (const unsigned char *)source;
    for (size_t index = 0; index < length; ++index) output[index] = input[index];
    return destination;
}

void *memset(void *destination, int value, size_t length) {
    unsigned char *output = (unsigned char *)destination;
    for (size_t index = 0; index < length; ++index) output[index] = (unsigned char)value;
    return destination;
}

int memcmp(const void *left, const void *right, size_t length) {
    const unsigned char *first = (const unsigned char *)left;
    const unsigned char *second = (const unsigned char *)right;
    for (size_t index = 0; index < length; ++index) {
        if (first[index] != second[index]) return (int)first[index] - (int)second[index];
    }
    return 0;
}

