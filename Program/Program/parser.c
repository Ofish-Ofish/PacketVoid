#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>

typedef enum action {
	DROP = 1,
	DELAY = 2,
	DUP = 3,
	CORRUPT = 4,

} Action;

typedef enum dir {
	DIR_IN,
	DIR_OUT,
	DIR_BOTH
} Dir;

typedef enum proto {
	ANY,
	TCP,
	UDP,
	ICMP
} Proto;;

typedef struct {
	Action action;
	UINT32 ip;
	Proto protorol;
	int port;
	int rate;
	Dir direction;
	int delayMs;

} FaultRule;