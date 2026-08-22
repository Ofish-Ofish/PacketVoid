#ifndef PARSER_H
#define PARSER_H

typedef void* FAULTRULE;

FAULTRULE* createRulesArray(int argc, char* argv[]);
int destroyRulesArray(FAULTRULE* rulesArray);

#endif