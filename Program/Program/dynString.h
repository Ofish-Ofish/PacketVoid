#ifndef DYNSTRING_H
#define DYNSTRING_H

#include "status.h"

typedef void* DYNSTRING;

DYNSTRING dynStringInit(void);
Status dynStringAppend(DYNSTRING hString, const char* text);
const char* dynStringCStr(DYNSTRING hString);
void dynStringDestroy(DYNSTRING* phString);

#endif