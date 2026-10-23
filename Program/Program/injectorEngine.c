#define WIN32_LEAN_AND_MEAN
#define PACKET_BUF_SIZE 65535

#include <ws2tcpip.h>
#include <winsock2.h>
#include <windivert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#pragma comment(lib, "ws2_32.lib")
#include "injectorEngine.h"
#include "rule.h"

typedef void* DELAYQUEUE;

typedef struct {
    bool outbound;
    Proto proto;
    uint32_t srcIp;
    uint32_t dstIp;
    int srcPort;
    int dstPort;
} PacketInfo;

typedef struct {
    HANDLE handle;
    RULELIST rules;
    DELAYQUEUE queue;
    bool verbose;
} Engine;

static Status buildFilter(RULELIST hRules, char* out, size_t outSize);

static Status packetParse(const void* data, UINT len, bool outbound, PacketInfo* out);
static void packetLog(const PacketInfo* info);
static Status packetCorrupt(void* data, UINT len, bool fixChecksum);

static bool ruleMatches(FAULTRULE hRule, const PacketInfo* info);
static bool rollRate(int rate);

static Status sendPacket(Engine* e, const void* packet, UINT len, const WINDIVERT_ADDRESS* addr);
static void delaySendCallback(void* ctx, const void* packet, uint32_t len, const void* addr, size_t addrSize);
static void applyRule(Engine* e, FAULTRULE r, char* packet, UINT len, WINDIVERT_ADDRESS* addr);
static void processPacket(Engine* e, char* packet, UINT len, WINDIVERT_ADDRESS* addr);

ENGINE engineInit(RULELIST hRules, bool verbose) {
    Engine* pEngine = (Engine*)malloc(sizeof(Engine));

    if (pEngine == NULL) {
        return NULL;
    }

    pEngine->rules = hRules;
    pEngine->queue = NULL;
    pEngine->verbose = verbose;

    pEngine->handle = WinDivertOpen("tcp or udp", WINDIVERT_LAYER_NETWORK, 0, 0);

    if (pEngine->handle == INVALID_HANDLE_VALUE) {
        printf("Error: Failed to open WinDivert. Are you running as Administrator?\n");
        free(pEngine);
        return NULL;
    }

    return pEngine;
}

static Status packetParse(const void* data, UINT len, bool outbound, PacketInfo* out) {
    PWINDIVERT_IPHDR ipHeader = NULL;
    PWINDIVERT_ICMPHDR icmpHeader = NULL;
    PWINDIVERT_TCPHDR tcpHeader = NULL;
    PWINDIVERT_UDPHDR udpHeader = NULL;

    WinDivertHelperParsePacket(
        data, len,
        &ipHeader, NULL,
        NULL,               
        &icmpHeader, NULL,
        &tcpHeader, &udpHeader,
        NULL, NULL,
        NULL, NULL
    );


    if (ipHeader == NULL) {
        return FAILURE;
    }

    out->outbound = outbound;
    out->proto = ANY;
    out->srcPort = -1;
    out->dstPort = -1;

    if (tcpHeader != NULL) {
        out->proto = TCP;
        out->srcPort = ntohs(tcpHeader->SrcPort);
        out->dstPort = ntohs(tcpHeader->DstPort);
    }
    else if (udpHeader != NULL) {
        out->proto = UDP;
        out->srcPort = ntohs(udpHeader->SrcPort);
        out->dstPort = ntohs(udpHeader->DstPort);
    }
    else if (icmpHeader != NULL) {
        out->proto = ICMP;
    }

    out->srcIp = ipHeader->SrcAddr;
    out->dstIp = ipHeader->DstAddr;

    return SUCCESS;
}

static void packetLog(const PacketInfo* info) {
    const char* direction = info->outbound ? "OUTBOUND" : "INBOUND";
    const char* protocol;

    if (info->proto == TCP) {
        protocol = "TCP";
    }
    else if (info->proto == UDP) {
        protocol = "UDP";
    }
    else if (info->proto == ICMP) {
        protocol = "ICMP";
    }
    else {
        protocol = "OTHER";
    }

    struct in_addr src, dst;
    char srcStr[INET_ADDRSTRLEN];
    char dstStr[INET_ADDRSTRLEN];

    src.s_addr = info->srcIp;
    dst.s_addr = info->dstIp;
    inet_ntop(AF_INET, &src, srcStr, sizeof(srcStr));
    inet_ntop(AF_INET, &dst, dstStr, sizeof(dstStr));

    if (info->srcPort >= 0) {
        printf("[%s][%s] %s:%d -> %s:%d\n", direction, protocol, srcStr, info->srcPort, dstStr, info->dstPort);
    }
    else {
        printf("[%s][%s] %s -> %s\n", direction, protocol, srcStr, dstStr);
    }
}

static Status sendPacket(Engine* e, const void* packet, UINT len, const WINDIVERT_ADDRESS* addr) {
    if (WinDivertSend(e->handle, packet, len, NULL, addr)) {
        return SUCCESS;
    }
    return FAILURE;
}

static void processPacket(Engine* e, char* packet, UINT len, WINDIVERT_ADDRESS* addr) {
    PacketInfo info;

    if (packetParse(packet, len, addr->Outbound, &info) == SUCCESS) {
        if (e->verbose) {
            packetLog(&info);
        }
    }

    if (sendPacket(e, packet, len, addr) != SUCCESS && e->verbose) {
        printf("[Engine] Failed to re-inject packet (len: %u)\n", len);
    }
}

void engineDestroy(ENGINE* phEngine) {
    Engine* pEngine = (Engine*)*phEngine;
    WinDivertClose(pEngine->handle);
    free(pEngine);
    *phEngine = NULL;
}

Status engineRun(ENGINE hEngine) {
    Engine* e = (Engine*)hEngine;
    char* packet = malloc(PACKET_BUF_SIZE);
    if (packet == NULL) {
        return FAILURE;
    }
    UINT len;
    WINDIVERT_ADDRESS addr;

    while (true) {
        if (!WinDivertRecv(e->handle, packet, PACKET_BUF_SIZE, &len, &addr)) {
            if (GetLastError() == ERROR_NO_DATA) {
                break;
            }
            continue;
        }
        processPacket(e, packet, len, &addr);
    }
    free(packet);
    return SUCCESS;
}

// int engineApplyRule() {
//     return 0;
// }

// int engineStartLoop() {
//     char packet[65535]; //(65535 is max IP packet size)
//     UINT packetLen;
//     WINDIVERT_ADDRESS recvAddr;
//     PWINDIVERT_IPHDR ipHeader;
//     PWINDIVERT_IPV6HDR ipv6Header;
//     PWINDIVERT_ICMPHDR icmpHeader;
//     PWINDIVERT_ICMPV6HDR icmpv6Header;
//     PWINDIVERT_TCPHDR tcpHeader;
//     PWINDIVERT_UDPHDR udpHeader;
//     // 4. The Intercept Loop
//     while (true) {
//         if (!WinDivertRecv(windivertHandle, packet, sizeof(packet), &packetLen, &recvAddr)) {
//             // Stop if handle is closed or an error occurs
//             break;
//         }

//         ipHeader = NULL;
//         ipv6Header = NULL;
//         icmpHeader = NULL;
//         icmpv6Header = NULL;
//         tcpHeader = NULL;
//         udpHeader = NULL;

//         WinDivertHelperParsePacket(
//             packet, packetLen,
//             &ipHeader, &ipv6Header,
//             NULL,               
//             &icmpHeader, &icmpv6Header,
//             &tcpHeader, &udpHeader,
//             NULL, NULL,
//             NULL, NULL
//         );
//         const char* ipVersion = ipHeader ? "IPv4" : (ipv6Header ? "IPv6" : "Unknown");
//         const char* direction = recvAddr.Outbound ? "OUTBOUND" : "INBOUND";

//         char srcStr[INET6_ADDRSTRLEN] = "?";
//         char dstStr[INET6_ADDRSTRLEN] = "?";
//         if (ipHeader != NULL) {
//             struct in_addr src, dst;
//             src.s_addr = ipHeader->SrcAddr;
//             dst.s_addr = ipHeader->DstAddr;
//             inet_ntop(AF_INET, &src, srcStr, sizeof(srcStr));
//             inet_ntop(AF_INET, &dst, dstStr, sizeof(dstStr));
//         }
//         else if (ipv6Header != NULL) {
//             inet_ntop(AF_INET6, ipv6Header->SrcAddr, srcStr, sizeof(srcStr));
//             inet_ntop(AF_INET6, ipv6Header->DstAddr, dstStr, sizeof(dstStr));
//         }

//         if (tcpHeader != NULL) {
//             UINT16 srcPort = ntohs(tcpHeader->SrcPort);
//             UINT16 dstPort = ntohs(tcpHeader->DstPort);
//             printf("[%s][%s][TCP] %s:%u -> %s:%u Flags=%s%s%s%s%s%s\n",
//                 direction, ipVersion, srcStr, srcPort, dstStr, dstPort,
//                 tcpHeader->Syn ? "SYN " : "",
//                 tcpHeader->Ack ? "ACK " : "",
//                 tcpHeader->Fin ? "FIN " : "",
//                 tcpHeader->Rst ? "RST " : "",
//                 tcpHeader->Psh ? "PSH " : "",
//                 tcpHeader->Urg ? "URG " : "");
//         }
//         else if (udpHeader != NULL) {
//             UINT16 srcPort = ntohs(udpHeader->SrcPort);
//             UINT16 dstPort = ntohs(udpHeader->DstPort);
//             printf("[%s][%s][UDP] %s:%u -> %s:%u\n",
//                 direction, ipVersion, srcStr, srcPort, dstStr, dstPort);
//         }
//         else if (icmpHeader != NULL) {
//             printf("[%s][%s][ICMP] %s -> %s Type=%u Code=%u\n",
//                 direction, ipVersion, srcStr, dstStr,
//                 icmpHeader->Type, icmpHeader->Code);
//         }
//         else if (icmpv6Header != NULL) {
//             printf("[%s][%s][ICMPv6] %s -> %s Type=%u Code=%u\n",
//                 direction, ipVersion, srcStr, dstStr,
//                 icmpv6Header->Type, icmpv6Header->Code);
//         }
//         else if (ipHeader != NULL) {
//             printf("[%s][%s][PROTO %u] %s -> %s\n",
//                 direction, ipVersion, ipHeader->Protocol, srcStr, dstStr);
//         }
//         else if (ipv6Header != NULL) {
//             printf("[%s][%s][PROTO %u] %s -> %s\n",
//                 direction, ipVersion, ipv6Header->NextHdr, srcStr, dstStr);
//         }
//         else {
//             printf("[%s][Unknown] Unparsed packet, Len=%u\n", direction, packetLen);
//         }

//         // (Fault logic will go here in the next phase)
//         // Push the unmodified packet back into the network stack
//         WinDivertSend(windivertHandle, packet, packetLen, &packetLen, &recvAddr);
//     }
//     return 0;
// }

// void engineDestroy() {
//     if (windivertHandle != NULL && windivertHandle != INVALID_HANDLE_VALUE) {
//         WinDivertClose(windivertHandle);
//         windivertHandle = NULL;
//     }
// }
