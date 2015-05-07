#pragma once
#include "struct.h"
#include "Ntos.h"
#include "InlineHook.h"
#include "KernelReload.h"
#define NOTIFY_ADDRESS_CALC_ONE(x) ((x) & ~7)
#define HIGH_12BIT_OF_ULONG(x)  ((ULONG)((x)>>20))
#define HIGH_BYTE_OF_ULONG(x)  ((BYTE)((x)>>24))
//////////////////////////////////////////////////////////////////////////
//typedef struct _NOTIFY_INFO{
//	ULONG dwPsCallImageNotifyRoutines;
//	ULONG dwReloadPsCallImageNotifyRoutines;
//	//
//
//}NOTIFY_INFO,*PNOTIFY_INFO;

VOID HookPsCallImageNotifyRoutines();
VOID UnhookPsCallImageNotifyRoutines();
VOID PatchReloadPspCreateThread();
BOOL InitNotifyRoutineAddr();
VOID RemoveNotifyRoutines();