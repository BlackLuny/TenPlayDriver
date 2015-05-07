#pragma once
#include "struct.h"
#include "GameInfo.h"
#include "UtilityFunc.h"
#include "HookPort.h"
typedef struct _SYSTEM_THREAD{
	PETHREAD EthreadObject;
	BOOL bAbortThread;
}SYSTEM_THREAD,*PSYSTEM_THREAD;
//
typedef VOID (_stdcall *PFN_KESTACKATTACHPROCESS)(
	__inout PRKPROCESS PROCESS,
	__out PKAPC_STATE ApcState
	);

typedef VOID (_stdcall *PFN_KEUNSTACKDETACHPROCESS)(
	__in PKAPC_STATE ApcState
	);


//NTSTATUS avSetDeleteThread();
//VOID avRemoveDeleteThread();
//VOID KillDxfProcess();
//VOID ReplaceDxfFiles();
//VOID avDeleteDxfFile(const WCHAR *filePath);
