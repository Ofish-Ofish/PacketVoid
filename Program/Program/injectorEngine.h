#ifndef INJECTORENGINE_H
#define INJECTORENGINE_H

#include <stdbool.h>
#include "status.h"
#include "ruleList.h"

typedef void* ENGINE;

ENGINE engineInit(RULELIST hRules, bool verbose);
Status engineRun(ENGINE hEngine);
void engineStop(ENGINE hEngine);
void engineDestroy(ENGINE* phEngine);

#endif