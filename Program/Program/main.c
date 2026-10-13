#include <stdio.h>
#include <stdlib.h>
#include "injectorEngine.h"
#include "parser.h"

int main(int argc, char* argv[]) {

	printf("PacketVoid Network Fault Injector v1.0\n");

    FAULTRULE* rulesArray;

    rulesArray = createRulesArray(argc, argv);

    return 0;

    printf("Starting PacketVoid Network Fault Injector...\n");

    if (engineInitDefault() != 0) {
        printf("Failed to initialize engine.\n");
        return 1;
    }

    printf("Starting packet interception loop. Press Ctrl+C to stop.\n");

    int result = engineStartLoop();

    if (result != 0) {
        printf("Engine loop exited with an error.\n");
    }

    engineDestroy();
    printf("Injector shut down gracefully.\n");

    return 0;
}