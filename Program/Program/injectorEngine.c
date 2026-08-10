#include <stdio.h>
#include <stdlib.h>

#include "injectorEngine.h"

typedef struct {
    int drop_percent;
    int duplicate_percent;
    int target_port;
    bool is_ipv6;
} FaultRule;

