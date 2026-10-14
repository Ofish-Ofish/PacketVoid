#ifndef RULELIST_H
#define RULELIST_H

#include <stdbool.h>
#include "rule.h"
#include "status.h"

typedef void* RULELIST;

// constactor
RULELIST ruleListInit(void);

//getters
int ruleListGetSize(RULELIST hRuleList);
int ruleListGetCapacity(RULELIST hRuleList);

FAULTRULE ruleListAt(RULELIST hRuleList, int i);
bool ruleListIsEmpty(RULELIST hRuleList);

//setters
Status ruleListPushBack(RULELIST hRuleList, FAULTRULE hRule);

//destructor
void ruleListDestroy(RULELIST* phRuleList);

#endif