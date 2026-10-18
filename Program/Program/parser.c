#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <limits.h>
#include "parser.h"
#include "ruleList.h"
#include "rule.h"

static Status parseInt(const char* text, int* out);

static Action parseAction(const char* text);

static bool isParamValidForAction(Action action, const char* key);

static Status applyParam(FAULTRULE rule, const char* key, const char* value);

static Status parseParams(FAULTRULE rule, char* paramStr);

static FAULTRULE parseRule(const char* actionText, char* paramText);

static Status parseInt(const char* hText, int* out) {
    if (hText == NULL || *hText == '\0') {
        return FAILURE;
    }

    char *pEnd;
    errno = 0;
    
    long val = strtol(hText, &pEnd, 10);

    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || 
        (val > INT_MAX || val < INT_MIN)) {
        return FAILURE; 
    }

    if (pEnd == hText) {
        return FAILURE; 
    }

    if (*pEnd != '\0') {
        return FAILURE; 
    }

    *out = (int)val;
    return SUCCESS;
}

static Action parseAction(const char* text) {
    if (text == NULL) {
        return NO_ACTION;
    }

    if (strcmp(text, "--drop") == 0) {
        return DROP;
    }
    else if (strcmp(text, "--delay") == 0) {
        return DELAY;
    }
    else if(strcmp(text, "--dup") == 0) {
        return DUP;
    }
    else if (strcmp(text, "--corrupt") == 0) {
        return CORRUPT;
    }
    return NO_ACTION;
}

static bool isParamValidForAction(Action action, const char* key) {
    if (strcmp(key, "ip") == 0 || strcmp(key, "port") == 0 ||
        strcmp(key, "proto") == 0 || strcmp(key, "dir") == 0) {
        return true;
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
        return false;
    }
}

static Status applyParam(FAULTRULE rule, const char* key, const char* value) {
    int val = 0;
    if (!isParamValidForAction(getRuleAction(rule), key)) {
        printf("Error: Parameter '%s' is not valid for this action.\n", key);
        return FAILURE;
    }
    if (strcmp(key, "port") == 0) {
        if (parseInt(value, &val) == FAILURE || setRulePort(rule, val) == FAILURE)  {
            printf("Error: Invalid port value '%s'.\n", value);
            return FAILURE;
        }
    }
    else if (strcmp(key, "rate") == 0) {
        if (parseInt(value, &val) == FAILURE || setRuleRate(rule, val) == FAILURE) {
            printf("Error: Invalid rate value '%s'.\n", value);
            return FAILURE;
        }
    }
    else if (strcmp(key, "ms") == 0) {
        if (parseInt(value, &val) == FAILURE || setRuleDelayMs(rule, val) == FAILURE) {
            printf("Error: Invalid delayMs value '%s'.\n", value);
            return FAILURE;
        }
    }
    else if (strcmp(key, "proto") == 0) {
        if (strcmp(value, "tcp") == 0) setRuleProtocol(rule, TCP);
        else if (strcmp(value, "udp") == 0) setRuleProtocol(rule, UDP);
        else if (strcmp(value, "icmp") == 0) setRuleProtocol(rule, ICMP);
        else {
            printf("Error: Unknown protocol '%s'.\n", value);
            return FAILURE;
        }
    }
    else if (strcmp(key, "dir") == 0) {
        if (strcmp(value, "in") == 0) setRuleDir(rule, DIR_IN);
        else if (strcmp(value, "out") == 0) setRuleDir(rule, DIR_OUT);
        else if (strcmp(value, "both") == 0) setRuleDir(rule, DIR_BOTH);
        else {
            printf("Error: Unknown direction '%s'.\n", value);
            return FAILURE;
        }
    }
    else if (strcmp(key, "ip") == 0) {
        struct in_addr addr;
        if (inet_pton(AF_INET, value, &addr) != 1) {
            printf("Error: Invalid IP address '%s'.\n", value);
            return FAILURE;
        }
        setRuleIp(rule, addr.s_addr);
    }
    else {
        printf("Error: Unknown parameter '%s'.\n", key);
        return FAILURE;
    }
    return SUCCESS;
}

static Status parseParams(FAULTRULE rule, char* paramStr) {
    char* context = NULL;
    char* rulePairs = strtok_s(paramStr, ",", &context);

    while (rulePairs != NULL) {
        char* equalSignAdress = strchr(rulePairs, '=');
        if (equalSignAdress == NULL) {
            printf("Error: Malformed parameter '%s'. Expected 'key=value'.\n", rulePairs);
            return FAILURE;
        }

        *equalSignAdress = '\0';
        char* key = rulePairs;
        char* value = equalSignAdress + 1;

        if (applyParam(rule, key, value) != SUCCESS) {
            return FAILURE;
        }

        rulePairs = strtok_s(NULL, ",", &context);
    }
    return SUCCESS;
}

static FAULTRULE parseRule(const char* actionStr, char* paramStr) {
    Action action = parseAction(actionStr);
    if (action == NO_ACTION) {
        printf("Error: Unknown action '%s'.\n", actionStr);
        return NULL;
    }
    FAULTRULE rule = ruleInit();
    if (rule == NULL) {
        return NULL;
    }   

    setRuleAction(rule, action);
    
    if (parseParams(rule, paramStr) == FAILURE) {
        ruleDestroy(&rule);
        return NULL;
    }

    return rule;
}

RULELIST parseArgs(int argc, char* argv[]) {

    if (argc < 3 || (argc - 1) % 2 != 0) {
        printf("Usage: %s --ACTION key=value,... [--ACTION key=value,...]\n", argv[0]);
        return NULL;
    }

    RULELIST rulesArray = ruleListInit();

    if (rulesArray == NULL) {
        printf("Error: Failed to allocate memory for rules array.\n");
        return NULL;
    }

    for (int i = 1; i < argc; i+=2)  {
        FAULTRULE rule = parseRule(argv[i], argv[i + 1]);
        if (rule == NULL) {
            ruleListDestroy(&rulesArray);
            return NULL;
        }
        if (ruleListPushBack(rulesArray, rule) != SUCCESS) {
            ruleDestroy(&rule);
            ruleListDestroy(&rulesArray);
            return NULL;
        }
    }

    return rulesArray;
}