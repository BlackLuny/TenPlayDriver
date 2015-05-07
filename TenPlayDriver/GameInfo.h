#pragma once
#include "struct.h"
//游戏进程数量
#define  GAME_PROCESS_COUNT 9
#define  DANGER_PROCESS_COUNT 6
extern CHAR GameProcessName[][30];
extern CHAR DangerProcessName[][30];
#pragma  pack (push,1)  
typedef struct _GameInformation{
	PVOID DriverBase;
	ULONG DriverSize;
	PDRIVER_OBJECT DriverObj;
	UNICODE_STRING uDriverName;
	//还可以扩展其他信息
}GameInformation,*PGameInformation;
#pragma  pack (pop) 
GameInformation GameInfo;

