#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windivert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#pragma comment(lib, "ws2_32.lib")

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
    const char* filter = "tcp or udp";

    // 2. Open the WinDivert handle
    windivertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (windivertHandle == INVALID_HANDLE_VALUE) {
        printf("CRITICAL: Failed to open WinDivert handle. Are you running as Administrator?\n");
        return -1;
    }

    printf("WinDivert handle opened successfully. Intercepting traffic...\n");

    char packet[65535]; //(65535 is max IP packet size)
    UINT packetLen;
    WINDIVERT_ADDRESS recvAddr;
    PWINDIVERT_IPHDR ipHeader;
    PWINDIVERT_IPV6HDR ipv6Header;
    PWINDIVERT_TCPHDR tcpHeader;
    PWINDIVERT_UDPHDR udpHeader;

    // 4. The Intercept Loop
    while (true) {
        // Pull a packet from the network stack
        if (!WinDivertRecv(windivertHandle, packet, sizeof(packet), &packetLen, &recvAddr)) {
            // Stop if handle is closed or an error occurs
            break;
        }

        ipHeader = NULL;
        ipv6Header = NULL;
        tcpHeader = NULL;
        udpHeader = NULL;

        WinDivertHelperParsePacket(
            packet, packetLen,
            &ipHeader, &ipv6Header,
            NULL, NULL, NULL,
            &tcpHeader, &udpHeader,
            NULL, NULL,
            NULL, NULL
        );

        const char* ipVersion = ipHeader ? "IPv4" : (ipv6Header ? "IPv6" : "Unknown");
        const char* direction = recvAddr.Outbound ? "OUTBOUND" : "INBOUND";
        UINT16 srcPort = 0, dstPort = 0;
        const char* proto = "Unknown";

        if (tcpHeader != NULL) {
            proto = "TCP";
            srcPort = ntohs(tcpHeader->SrcPort);
            dstPort = ntohs(tcpHeader->DstPort);
        }
        else if (udpHeader != NULL) {
            proto = "UDP";
            srcPort = ntohs(udpHeader->SrcPort);
            dstPort = ntohs(udpHeader->DstPort);
        }

        if (tcpHeader != NULL || udpHeader != NULL) {
            printf("[%s][%s][%s] SrcPort=%u DstPort=%u\n",
                direction, ipVersion, proto, srcPort, dstPort);
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
