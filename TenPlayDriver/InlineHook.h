#ifndef _INLINEHOOK_H_
#define _INLINEHOOK_H_
#include "struct.h"
#include "UtilityFunc.h"

#define  NOP_CODE	0x90
#define  JMP_CODE	0xe9
//
#define  MAX_PATCH_LENGTH 16
#define  MIN_PATCH_LENGTH 5
//机器码与地址的换算长度 B = C - A - 5
#define  OPCODE_CALC_LENGTH 5
#define  JMP_LENGTH 5
//代码力求规范化
#pragma pack(push,1)
typedef struct _INLINE_HOOK_INFO{
	PVOID lpOriginAddr;
	PVOID lpNewAddr;
	ULONG dwPatchLength;
	PVOID lpRetAddr;
	PVOID lpHookZoneAddr;
	/*BOOL bCommState;*/
}INLINE_HOOK_INFO,*PINLINE_HOOK_INFO;
//
//typedef struct _MIDDLE_HOOK_INFO{
//	PVOID lpOriginAddr;
//	PVOID lpNewAddr;
//	ULONG dwPatchLength;
//	PVOID lpRetAddr;
//	PVOID lpHookZoneAddr;
//	/*BOOL bCommState;*/
//}MIDDLE_HOOK_INFO,*PMIDDLE_HOOK_INFO;
#pragma  pack(pop)
BOOL HookFunctionByHeaderAddress(INLINE_HOOK_INFO *lpHookInfo);

VOID UnHookFunctionByHeaderAddress(INLINE_HOOK_INFO *lpHookInfo);
//
ULONG SeachSignCode(BYTE *pStartAddress,
	ULONG dwMaxLength,
	BYTE bySignCode[],
	ULONG dwCodeCount);
#endif

