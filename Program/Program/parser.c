#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include "parser.h"
#include "ruleList.h"
#include "rule.h"

bool isParamValidForAction(Action action, const char* key) {
    if (strcmp(key, "ip") == 0 || strcmp(key, "port") == 0 ||
        strcmp(key, "proto") == 0 || strcmp(key, "dir") == 0) {
        return false;
    }

    switch (action) {
    case DROP:
    case DUP:
        return strcmp(key, "rate") == 0;

    case DELAY:
        return strcmp(key, "ms") == 0;

    case CORRUPT:
        return strcmp(key, "rate") == 0;

    default:
        return 0;
    }
}

int applyParam(FAILURE rule, char* key, char* value) {
    if (!isParamValidForAction(rule->action, key)) {
        printf("Error: Parameter '%s' is not valid for this action.\n", key);
        return -1;
    }

    if (strcmp(key, "port") == 0) {
        char* endptr;
        long port = strtol(value, &endptr, 10);
        if (*endptr != '\0' || port < 0 || port > 65535) {
            printf("Error: Invalid port value '%s'.\n", value);
            return -1;
        }
        setRulePort(rule, (int)port);
    }
    else if (strcmp(key, "rate") == 0) {
        char* endptr;
        long rate = strtol(value, &endptr, 10);
        if (*endptr != '\0' && strcmp(endptr, "%") != 0) {
            printf("Error: Invalid rate value '%s'.\n", value);
            return -1;
        }
        setRuleRate(rule, (int)rate);
    }
    else if (strcmp(key, "ms") == 0) {
        char* endptr;
        long ms = strtol(value, &endptr, 10);
        if (*endptr != '\0' || ms < 0) {
            printf("Error: Invalid ms value '%s'.\n", value);
            return -1;
        }
        setRuleDelayMs(rule, (int)ms);
    }
    else if (strcmp(key, "proto") == 0) {
        if (strcmp(value, "tcp") == 0) setRuleProtocol(rule, TCP);
        else if (strcmp(value, "udp") == 0) setRuleProtocol(rule, UDP);
        else if (strcmp(value, "icmp") == 0) setRuleProtocol(rule, ICMP);
        else {
            printf("Error: Unknown protocol '%s'.\n", value);
            return -1;
        }
    }
    else if (strcmp(key, "dir") == 0) {
        if (strcmp(value, "in") == 0) rule->direction = DIR_IN;
        else if (strcmp(value, "out") == 0) rule->direction = DIR_OUT;
        else if (strcmp(value, "both") == 0) rule->direction = DIR_BOTH;
        else {
            printf("Error: Unknown direction '%s'.\n", value);
            return -1;
        }
    }
    else if (strcmp(key, "ip") == 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, value, &addr) != 1) {
            printf("Error: Invalid IP address '%s'.\n", value);
            return -1;
        }
        setRuleIp(rule, addr);
    }
    else {
        printf("Error: Unknown parameter '%s'.\n", key);
        return -1;
    }
    return 0;
}

static int parseParamString(FAILURE rule, char* paramStr) {
    char* context = NULL;
    char* token = strtok_s(paramStr, ",", &context);
    while (token != NULL) {
        char* eq = strchr(token, '=');
        if (eq == NULL) {
            printf("Error: Malformed parameter '%s'. Expected 'key=value'.\n", token);
            return -1;
        }
        *eq = '\0';
        char* key = token;
        char* value = eq + 1;

        if (applyParam(rule, key, value) != 0) {
            return -1;
        }

        token = strtok_s(NULL, ",", &context);
    }
    return 0;
}

RULELIST createRulesArray(int argc, char* argv[]) {
    int i = 1;
    int j = 0;
    RULELIST* rulesArray = ruleListInit();
    
    if (rulesArray == NULL) {
        printf("Error: Failed to allocate memory for rules array.\n");
        return NULL;
    }

    while (i < argc) {
        if (strncmp(argv[i], "--", 2)) {
            printf("Error: Invalid argument format. Expected '--ACTION'.\n");
            free(rulesArray);
            return NULL;
        }

        FAULTRULE rule = ruleInit();

        if (strncmp(argv[i], "--drop", 6) == 0) {
            setRuleAction(rule, DROP);
        }
        else if (strncmp(argv[i], "--delay", 7) == 0) {
            setRuleAction(rule, DELAY);
        }
        else if (strncmp(argv[i], "--dup", 5) == 0) {
            setRuleAction(rule, DUP);
        }
        else if (strncmp(argv[i], "--corrupt", 9) == 0) {
            setRuleAction(rule, CORRUPT);
        }
        else {
            printf("Error: Unknown action '%s'.\n", argv[i]);
            ruleListDestroy(rulesArray);
            return NULL;
        }

        if (i + 1 >= argc) {
            printf("Error: Missing parameters for action '%s'.\n", argv[i]);
            ruleListDestroy(rulesArray);
            return NULL;
        }

        char paramBuf[256];
        if (strncpy_s(paramBuf, sizeof(paramBuf), argv[i + 1], _TRUNCATE) != 0 && errno != STRUNCATE) {
            fprintf(stderr, "Error: Failed to copy parameter string.\n");
            ruleListDestroy(rulesArray);
            return NULL;
        }

        if (parseParamString(&rule, paramBuf) != 0) {
            ruleListDestroy(rulesArray);
            return NULL;
        }

        ruleListPushBack(rulesArray, rule);
        i += 2;
        j += 1;
    }
    return rulesArray;
}