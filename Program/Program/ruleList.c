#include "ruleList.h"
#include "rule.h"

typedef struct
{
	int size;
	int capacity; 
	FAULTRULE* rules;
} RuleList;

RULELIST ruleListInit(void);

//getters
int ruleListGetSize(RULELIST hRuleList);
int ruleListGetCapacity(RULELIST hRuleList);

FAULTRULE ruleListAt(RULELIST hRuleList, int i);
bool ruleListIsEmpty(RULELIST hRuleList);

//setters
Status ruleListPushBack(RULELIST hRuleList, FAULTRULE hRule);
Status ruleListPopBack(RULELIST hRuleList);

//destructor
void ruleListDestroy(RULELIST* phRuleList);
