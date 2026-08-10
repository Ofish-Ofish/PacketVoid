typedef struct {
    int drop_percent;
    int duplicate_percent;
    int target_port;
    bool is_ipv6;
} FaultRule;

int Engine_Initialize();
int Engine_ApplyRule(FaultRule* rule);
int Engine_StartLoop();
void Engine_Shutdown();