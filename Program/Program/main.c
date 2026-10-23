#include <stdio.h>
#include <stdlib.h>
#include "injectorEngine.h"
#include "parser.h"

int main(int argc, char* argv[]) {

	printf("PacketVoid Network Fault Injector v1.0\n");

    RULELIST* rulesArray;

    rulesArray = parseArgs(argc, argv);

    if (rules == NULL) {
        return 1;
    }

    ENGINE e = engineInit(rulesArray, true);

    if (e == NULL) {
        return 1;
    }

    printf("Starting PacketVoid Network Fault Injector...\n");
    printf("Starting packet interception loop. Press Ctrl+C to stop.\n");


    Status status = engineRun(e);

    if (status == FAILURE) {
        printf("Engine loop exited with an error.\n");
    }

    engineDestroy(&e);
    ruleListDestroy(&rules)
    printf("Injector shut down gracefully.\n");

    return 0;
}