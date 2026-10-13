#ifndef PARSER_H
#define PARSER_H
#include <winsock2.h>

typedef void* FAULTRULE;

typedef enum action {
    DROP = 1,
    DELAY = 2,
    DUP = 3,
    CORRUPT = 4,
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


//constructor
FAULTRULE* createRulesArray(int argc, char* argv[]);

//getters
Action getRuleAction(int index, FAULTRULE* array);
Proto getRuleProtocol(int index, FAULTRULE* array);
Dir getRuleDir(int index, FAULTRULE* array);
int getRulePort(int index, FAULTRULE* array);
int getRuleRate(int index, FAULTRULE* array);
int getRuleDelayMs(int index, FAULTRULE* array);
UINT32 getRuleIp(int index, FAULTRULE* array);

//destructor
int destroyRulesArray(FAULTRULE* rulesArray);

#endif