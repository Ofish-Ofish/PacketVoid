#include "ruleList.h"
#include "rule.h"

typedef struct
{
	int size;
	int capacity; 
	FAULTRULE* rules;
} RuleList;

RULELIST ruleListInit(void) {
	RuleList* ruleList = (RuleList*)malloc(sizeof(RuleList));

	if (ruleList == NULL) {
		return NULL;
	}

	ruleList->size = 0;
	ruleList->capacity = 1;
	ruleList->rules = (FAULTRULE*)malloc(sizeof(FAULTRULE) * ruleList->capacity);

	if (ruleList->rules == NULL) {
		free(ruleList);
		return NULL;
	}

	return ruleList;
}

//getters
int ruleListGetSize(RULELIST hRuleList) {
	RuleList* pRuleList = (RuleList*)hRuleList;
	return pRuleList->size;
}

int ruleListGetCapacity(RULELIST hRuleList) {
	RuleList* pRuleList = (RuleList*)hRuleList;
	return pRuleList->capacity;
}

FAULTRULE ruleListAt(RULELIST hRuleList, int i) {
	RuleList* pRuleList = (RuleList*)hRuleList;

	if (i < 0 || i >= pRuleList->size) {
		return NULL;
	}

	return pRuleList->rules[i];
}

bool ruleListIsEmpty(RULELIST hRuleList) {
	RuleList* pRuleList = (RuleList*)hRuleList;
	return pRuleList->size == 0 ? true : false;
}

//setters
Status ruleListPushBack(RULELIST hRuleList, FAULTRULE hRule) {
    RuleList* pRuleList = (RuleList*)hRuleList;

    if (pRuleList->size == pRuleList->capacity) {
        int newCapacity = pRuleList->capacity * 2;
        FAULTRULE* tmp = (FAULTRULE*)realloc(pRuleList->rules, sizeof(FAULTRULE) * newCapacity);

        if (tmp == NULL) {
            return FAILURE;
        }

        pRuleList->rules = tmp;
        pRuleList->capacity = newCapacity;
    }

    pRuleList->rules[pRuleList->size] = hRule;
    pRuleList->size++;
    return SUCCESS;
}

//destructor
void ruleListDestroy(RULELIST* phRuleList) {
	RuleList* pRuleList = (RuleList*)*phRuleList;

	for (int i = 0; i < pRuleList->size;  i++) {
		ruleDestroy(&pRuleList->rules[i]);
	}

	free(pRuleList->rules);
	free(pRuleList);
	*phRuleList = NULL;
}
