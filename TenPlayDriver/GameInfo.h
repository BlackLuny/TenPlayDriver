#pragma once
#include "struct.h"
//��Ϸ��������
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
	//��������չ������Ϣ
}GameInformation,*PGameInformation;
#pragma  pack (pop) 
GameInformation GameInfo;

