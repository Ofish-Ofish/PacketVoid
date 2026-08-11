#include <stdio.h>
#include <stdlib.h>
#include "injectorEngine.h"

int main() {
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