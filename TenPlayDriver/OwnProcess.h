#pragma once
#include "struct.h"
#include "UtilityFunc.h"
typedef struct _OWNPROCESS_INFO{
	PLIST_ENTRY pActiveBlink;
	PLIST_ENTRY pActiveFlink;
	PLIST_ENTRY pSessionBlink;
	PLIST_ENTRY pSessionFlink;
	PLIST_ENTRY pHandleBlink;
	PLIST_ENTRY pHandleFlink;
	PEPROCESS pProtectedProcess;
	ULONG dwPid;
	/*CHAR szOwnProcessName[30];*/
	UNICODE_STRING uOwnProcessFullPath;
}OWNPROCESS_INFO,*POWNPROCESS_INFO;
//
typedef struct _CID_TABLE{
	BOOL	EnumCallBackHideType;
	PHANDLE_TABLE_ENTRY PspHideCidTableEntry;
	PVOID HidePspObject;
}CID_TABLE,*PCID_TABLE;

typedef BOOL( *EX_ENUMERATE_HANDLE_ROUTINE )(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN OUT PVOID EnumParameter
	);

typedef BOOL( *PExEnumHandleTable )(
	IN PHANDLE_TABLE HandleTable,
	IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	IN PVOID EnumParameter,
	OUT PHANDLE Handle OPTIONAL
	);
NTSTATUS InitOwnProcess();
VOID HideOwnProcess();
VOID RecoverHideProcess();