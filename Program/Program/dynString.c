#include <stdlib.h>
#include <string.h>
#include "dynString.h"

typedef struct {
    char* data;
    size_t length;
    size_t capacity;
} DynString;

DYNSTRING dynStringInit(void) {
    DynString* pString = (DynString*)malloc(sizeof(DynString));
    if (pString == NULL) {
        return NULL;
    }

    pString->length = 0;
    pString->capacity = 64;
    pString->data = (char*)malloc(pString->capacity);
    if (pString->data == NULL) {
        free(pString);
        return NULL;
    }

    pString->data[0] = '\0';
    return pString;
}

Status dynStringAppend(DYNSTRING hString, const char* text) {
    DynString* pString = (DynString*)hString;
    size_t len = strlen(text);
    size_t needed = pString->length + len + 1;

    if (needed > pString->capacity) {
        size_t newCapacity = pString->capacity;
        while (newCapacity < needed) {
            newCapacity *= 2;
        }

        char* tmp = (char*)realloc(pString->data, newCapacity);
        if (tmp == NULL) {
            return FAILURE;
        }
        pString->data = tmp;
        pString->capacity = newCapacity;
    }

    memcpy(pString->data + pString->length, text, len + 1);
    pString->length += len;
    return SUCCESS;
}

const char* dynStringCStr(DYNSTRING hString) {
    return ((DynString*)hString)->data;
}

void dynStringDestroy(DYNSTRING* phString) {
    DynString* pString = (DynString*)*phString;
    free(pString->data);
    free(pString);
    *phString = NULL;
}