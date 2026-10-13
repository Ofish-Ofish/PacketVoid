#ifndef RULE_H
#define RULE_H
#include <winsock2.h>
#include "status.h"

typedef enum action {
    NO_ACTION,
    DROP,
    DELAY,
    DUP,
    CORRUPT
} Action;

typedef enum dir {
    DIR_IN,
    DIR_OUT,
    DIR_BOTH
} Dir;

typedef enum proto {
    ANY,
    TCP,
    UDP,
    ICMP
} Proto;

typedef void* FAULTRULE;

// constactor
FAULTRULE ruleInit(void);

/* getters */
Action getRuleAction(FAULTRULE hrule);
Proto getRuleProtocol(FAULTRULE hrule);
Dir getRuleDir(FAULTRULE hrule);
int getRulePort(FAULTRULE hrule);      /* -1 = any */
int getRuleRate(FAULTRULE hrule);      /* percent */
int getRuleDelayMs(FAULTRULE hrule);
UINT32 getRuleIp(FAULTRULE hrule);        /* network order, 0 = any */

Status setRuleAction(FAULTRULE hrule, Action action);
Status setRuleProtocol(FAULTRULE hrule, Proto protocol);
Status setRuleDir(FAULTRULE hrule, Dir direction);
Status setRulePort(FAULTRULE hrule, int port);
Status setRuleRate(FAULTRULE hrule, int rate);
Status setRuleDelayMs(FAULTRULE hrule, int ms);
Status setRuleIp(FAULTRULE hrule, UINT32 ip);


//destructor
void ruleDestroy(FAULTRULE* phrule);


#endif