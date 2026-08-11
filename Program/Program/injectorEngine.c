#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <windows.h>
#include "windivert.h"

#include "injectorEngine.h"


typedef struct {
    int drop_percent;
    int duplicate_percent;
    int target_port;
    bool is_ipv6;
} FaultRule;

static HANDLE windivertHandle = NULL;
static FaultRule activeRule = { 0 };

int engineInitDefault() {
    return 0;
}

int engineApplyRule(FALTRULE* hrule) {
    return 0;
}

int engineStartLoop() {
    // 1. The Filter String: Intercept ALL outbound TCP traffic to test
    const char* filter = "outbound and tcp";

    // 2. Open the WinDivert handle
    windivertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (windivertHandle == INVALID_HANDLE_VALUE) {
        printf("CRITICAL: Failed to open WinDivert handle. Are you running as Administrator?\n");
        return -1;
    }

    printf("WinDivert handle opened successfully. Intercepting traffic...\n");

    // 3. The Packet Buffer (65535 is max IP packet size)
    char packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS recvAddr;

    // 4. The Intercept Loop
    while (true) {
        // Pull a packet from the network stack
        if (!WinDivertRecv(windivertHandle, packet, sizeof(packet), &packetLen, &recvAddr)) {
            // Stop if handle is closed or an error occurs
            break;
        }

        // (Fault logic will go here in the next phase)

        // Push the unmodified packet back into the network stack
        WinDivertSend(windivertHandle, packet, packetLen, &packetLen, &recvAddr);
    }

    return 0;
}

void engineDestroy() {
    if (windivertHandle != NULL && windivertHandle != INVALID_HANDLE_VALUE) {
        WinDivertClose(windivertHandle);
        windivertHandle = NULL;
    }
}
