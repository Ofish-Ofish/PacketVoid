#ifndef injectorEngine_H
#define injectorEngine_H

#include "injectorEngine.h"

typedef void* FALTRULE;

int engineInitDefault();
int engineApplyRule(FALTRULE* hrule);
int engineStartLoop();
void engineDestroy();

#endif