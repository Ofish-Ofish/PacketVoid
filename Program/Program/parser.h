#ifndef parser_H
#define parser_H

#include "parser.h"


typedef void* FALTRULE;

FALTRULE* createRulesArray();

FALTRULE parseRule();

int destroyRulesArray(FALTRULE* rulesArray);



#endif