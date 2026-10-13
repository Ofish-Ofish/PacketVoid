#include <stdlib.h>
#include "rule.h"

typedef struct {
    Action action;
    UINT32 ip;
    Proto protocol;
    int port;
    int rate;
    Dir direction;
    int delayMs;
} FaultRule;

// constactor
FAULTRULE ruleInit(void) {
    FaultRule* pRule = (FaultRule*)malloc(sizeof(FaultRule));

    if (pRule == NULL) {
        return NULL;
    }

    pRule->action = NO_ACTION;
    pRule->ip = 0; //any
    pRule->protocol = ANY;
    pRule->port = -1; //any
    pRule->rate = 100; //%
    pRule->direction = DIR_BOTH;
    pRule->delayMs = 0;

    return pRule;

}

/* getters */
Action getRuleAction(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->action;
}

Proto getRuleProtocol(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->protocol;
}

Dir getRuleDir(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->direction;
}

int getRulePort(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->port;
}

int getRuleRate(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->rate;
}

int getRuleDelayMs(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->delayMs;
}

UINT32 getRuleIp(FAULTRULE hrule) {
    FaultRule* pRule = (FaultRule*)hrule;
    return pRule->ip;
}

Status setRuleAction(FAULTRULE hrule, Action action) {
    FaultRule* pRule = (FaultRule*)hrule;
    if (action != DROP && action != DELAY && action != DUP && action != CORRUPT) {
        return FAILURE;
    }
    pRule->action = action;
    return SUCCESS;
}

Status setRuleProtocol(FAULTRULE hrule, Proto protocol) {
    FaultRule* pRule = (FaultRule*)hrule;
    if (protocol != ANY && protocol != TCP && protocol != UDP && protocol != ICMP) {
        return FAILURE;
    }
    pRule->protocol = protocol;
    return SUCCESS;
}

Status setRuleDir(FAULTRULE hrule, Dir direction) {
    FaultRule* pRule = (FaultRule*)hrule;
    if (direction != DIR_IN && direction != DIR_OUT && direction != DIR_BOTH) {
        return FAILURE;
    }
    pRule->direction = direction;
    return SUCCESS;
}

Status setRulePort(FAULTRULE hrule, int port) {
    FaultRule* pRule = (FaultRule*)hrule;
    if (port < -1 || port > 65535) {
        return FAILURE;
    }
    pRule->port = port;
    return SUCCESS;
}

Status setRuleRate(FAULTRULE hrule, int rate) {
    FaultRule* pRule = (FaultRule*)hrule;
    if (rate < 0 || rate > 100) {
        return FAILURE;
    }
    pRule->rate = rate;
    return SUCCESS;
}

Status setRuleDelayMs(FAULTRULE hrule, int ms) {
    FaultRule* pRule = (FaultRule*)hrule;
    if (ms < 0) {
        return FAILURE;
    }
    pRule->delayMs = ms;
    return SUCCESS;
}
Status setRuleIp(FAULTRULE hrule, UINT32 ip) {
    FaultRule* pRule = (FaultRule*)hrule;
    pRule->ip = ip;
    return SUCCESS;
}

//destructor
void ruleDestroy(FAULTRULE* phrule) {
    FaultRule* pRule = (FaultRule*)*phrule;
    free(pRule);
    *phrule = NULL;
}