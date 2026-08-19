#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
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
    const char* filter = "tcp or udp";
    windivertHandle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (windivertHandle == INVALID_HANDLE_VALUE) {
        printf("CRITICAL: Failed to open WinDivert handle. Are you running as Administrator?\n");
        return -1;
    }

    printf("WinDivert handle opened successfully. Intercepting traffic...\n");
    return 0;
}

int engineApplyRule(FALTRULE* hrule) {
    return 0;
}

int engineStartLoop() {
    char packet[65535]; //(65535 is max IP packet size)
    UINT packetLen;
    WINDIVERT_ADDRESS recvAddr;
    PWINDIVERT_IPHDR ipHeader;
    PWINDIVERT_IPV6HDR ipv6Header;
    PWINDIVERT_ICMPHDR icmpHeader;
    PWINDIVERT_ICMPV6HDR icmpv6Header;
    PWINDIVERT_TCPHDR tcpHeader;
    PWINDIVERT_UDPHDR udpHeader;
    // 4. The Intercept Loop
    while (true) {
        if (!WinDivertRecv(windivertHandle, packet, sizeof(packet), &packetLen, &recvAddr)) {
            // Stop if handle is closed or an error occurs
            break;
        }

        ipHeader = NULL;
        ipv6Header = NULL;
        icmpHeader = NULL;
        icmpv6Header = NULL;
        tcpHeader = NULL;
        udpHeader = NULL;

        WinDivertHelperParsePacket(
            packet, packetLen,
            &ipHeader, &ipv6Header,
            NULL,               
            &icmpHeader, &icmpv6Header,
            &tcpHeader, &udpHeader,
            NULL, NULL,
            NULL, NULL
        );
        const char* ipVersion = ipHeader ? "IPv4" : (ipv6Header ? "IPv6" : "Unknown");
        const char* direction = recvAddr.Outbound ? "OUTBOUND" : "INBOUND";

        char srcStr[INET6_ADDRSTRLEN] = "?";
        char dstStr[INET6_ADDRSTRLEN] = "?";
        if (ipHeader != NULL) {
            struct in_addr src, dst;
            src.s_addr = ipHeader->SrcAddr;
            dst.s_addr = ipHeader->DstAddr;
            inet_ntop(AF_INET, &src, srcStr, sizeof(srcStr));
            inet_ntop(AF_INET, &dst, dstStr, sizeof(dstStr));
        }
        else if (ipv6Header != NULL) {
            inet_ntop(AF_INET6, ipv6Header->SrcAddr, srcStr, sizeof(srcStr));
            inet_ntop(AF_INET6, ipv6Header->DstAddr, dstStr, sizeof(dstStr));
        }

        if (tcpHeader != NULL) {
            UINT16 srcPort = ntohs(tcpHeader->SrcPort);
            UINT16 dstPort = ntohs(tcpHeader->DstPort);
            printf("[%s][%s][TCP] %s:%u -> %s:%u Flags=%s%s%s%s%s%s\n",
                direction, ipVersion, srcStr, srcPort, dstStr, dstPort,
                tcpHeader->Syn ? "SYN " : "",
                tcpHeader->Ack ? "ACK " : "",
                tcpHeader->Fin ? "FIN " : "",
                tcpHeader->Rst ? "RST " : "",
                tcpHeader->Psh ? "PSH " : "",
                tcpHeader->Urg ? "URG " : "");
        }
        else if (udpHeader != NULL) {
            UINT16 srcPort = ntohs(udpHeader->SrcPort);
            UINT16 dstPort = ntohs(udpHeader->DstPort);
            printf("[%s][%s][UDP] %s:%u -> %s:%u\n",
                direction, ipVersion, srcStr, srcPort, dstStr, dstPort);
        }
        else if (icmpHeader != NULL) {
            printf("[%s][%s][ICMP] %s -> %s Type=%u Code=%u\n",
                direction, ipVersion, srcStr, dstStr,
                icmpHeader->Type, icmpHeader->Code);
        }
        else if (icmpv6Header != NULL) {
            printf("[%s][%s][ICMPv6] %s -> %s Type=%u Code=%u\n",
                direction, ipVersion, srcStr, dstStr,
                icmpv6Header->Type, icmpv6Header->Code);
        }
        else if (ipHeader != NULL) {
            printf("[%s][%s][PROTO %u] %s -> %s\n",
                direction, ipVersion, ipHeader->Protocol, srcStr, dstStr);
        }
        else if (ipv6Header != NULL) {
            printf("[%s][%s][PROTO %u] %s -> %s\n",
                direction, ipVersion, ipv6Header->NextHdr, srcStr, dstStr);
        }
        else {
            printf("[%s][Unknown] Unparsed packet, Len=%u\n", direction, packetLen);
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
