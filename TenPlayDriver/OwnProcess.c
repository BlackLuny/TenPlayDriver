#include "OwnProcess.h"
CHAR OwnProcessName[30] = "TianChen.exe";
CHAR OwnDmDll[30]="dm.dll";
WCHAR wOwnProcessName[30] = L"TianChen.exe";
WCHAR wOwnDmDll[30]= L"dm.dll";
//static CHAR OwnProcessName[30] = "taskmgr.exe";
static WCHAR OwnProcessFullPath[260]={0};
OWNPROCESS_INFO g_OwnInfo = {0};

// 指明遍历哪个句柄表,0表示全局句柄表
static CID_TABLE cid = {0};

NTSTATUS InitOwnProcess()
{
	NTSTATUS nStatus					= STATUS_UNSUCCESSFUL;
	PEPROCESS pProtectedProcess			= NULL;
	/*strcpy_s(&g_ProtectedProcess.szOwnProcessName[0],strlen(OwnProcessName),OwnProcessName);*/
	UNICODE_STRING uNtPath				= {0};
	WCHAR		*pNtPathBuffer			= NULL;
	UNICODE_STRING uDeviceName			={0};
	WCHAR		*pDeviceName			= NULL;
	nStatus = LookupProcessByName(OwnProcessName,&pProtectedProcess);
	if (!NT_SUCCESS(nStatus))
	{
		return nStatus;
	}
	g_OwnInfo.pProtectedProcess = pProtectedProcess;
	g_OwnInfo.dwPid = *(PULONG)((ULONG)pProtectedProcess+0x84);
	 /*+0x1f4 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO*/
	//pUniFullPath = (PUNICODE_STRING)*(PULONG)((ULONG)pProtectedProcess+0x1f4);
	RtlZeroMemory(OwnProcessFullPath,sizeof(OwnProcessFullPath));
	g_OwnInfo.uOwnProcessFullPath.Length = sizeof(OwnProcessFullPath);
	g_OwnInfo.uOwnProcessFullPath.MaximumLength = sizeof(OwnProcessFullPath);
	g_OwnInfo.uOwnProcessFullPath.Buffer = OwnProcessFullPath;

	pNtPathBuffer = (WCHAR *)ExAllocatePoolWithTag(PagedPool,260*sizeof(WCHAR),'link');
	if (!pNtPathBuffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pNtPathBuffer,260*sizeof(WCHAR));
	RtlInitEmptyUnicodeString(&uNtPath,pNtPathBuffer,260*sizeof(WCHAR));

	nStatus = avQueryProcessFullPath(pProtectedProcess,&uNtPath);

	if (!NT_SUCCESS(nStatus))
	{
		avPrint("avQueryProcessFullPath failed...");
		return nStatus;
	}
	pDeviceName = (WCHAR *)ExAllocatePoolWithTag(PagedPool,260*2,'link');
	if (!pDeviceName)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlZeroMemory(pDeviceName,260*sizeof(WCHAR));
	RtlInitEmptyUnicodeString(&uDeviceName,pDeviceName,260*sizeof(WCHAR));
	avGetDeviceNameFromNtPath(&uNtPath,&uDeviceName);

	nStatus = avRtlVolumeDeviceToDosName(&uDeviceName,&g_OwnInfo.uOwnProcessFullPath);
	if (!NT_SUCCESS(nStatus))
	{
		goto _ClearUp;
	}
	RtlAppendUnicodeToString(&g_OwnInfo.uOwnProcessFullPath,uNtPath.Buffer + uDeviceName.Length/sizeof(WCHAR));
	//获取程序所在目录名，不包括反斜线
	avGetDosDirFromDosFullPath(&g_OwnInfo.uOwnProcessFullPath);
	/*\Device\HarddiskVolume1\Documents and*/
	DbgPrint("OwnProcessFullPath : %wZ\n",&g_OwnInfo.uOwnProcessFullPath);
_ClearUp:
	if (pNtPathBuffer)
	{
		ExFreePool(pNtPathBuffer);
		pNtPathBuffer = NULL;
	}
	if (pDeviceName)
	{
		ExFreePool(pDeviceName);
		pDeviceName = NULL;
	}
	return nStatus;
}
//

//脱两条链表
NTSTATUS RemoveFromProcessLinks( PEPROCESS Eprocess )
{
	PLIST_ENTRY pList_Current;

	if( Eprocess == NULL )
	{
		return STATUS_UNSUCCESSFUL;
	}

	//
	// 开始脱链
	//
	pList_Current = ( PLIST_ENTRY )( ( ULONG ) Eprocess + 0x88 );

	if( pList_Current->Flink )
	{
		//保存一下
		g_OwnInfo.pActiveFlink = pList_Current->Flink;
		pList_Current->Blink->Flink = pList_Current->Flink;
	}

	if( pList_Current->Blink )
	{
		g_OwnInfo.pActiveBlink = pList_Current->Blink;
		pList_Current->Flink->Blink = pList_Current->Blink;
	}

	pList_Current->Flink = NULL;
	pList_Current->Blink = NULL;

	//
	// SessionProcessLinks
	//
	pList_Current = ( PLIST_ENTRY )( ( ULONG ) Eprocess + 0x0b4 );

	if( pList_Current->Blink && pList_Current->Blink->Flink )
	{
		g_OwnInfo.pSessionBlink = pList_Current->Blink;
		pList_Current->Blink->Flink = pList_Current->Flink;
	}

	if( pList_Current->Flink && pList_Current->Flink->Blink )
	{
		g_OwnInfo.pSessionFlink = pList_Current->Flink;
		pList_Current->Flink->Blink = pList_Current->Blink;
	}

	pList_Current->Flink = NULL;
	pList_Current->Blink = NULL;

	return  STATUS_SUCCESS;
}
//
VOID RemoveFromHandleTableList( PEPROCESS Eprocess)
{
	PLIST_ENTRY pList_Current;

	// WIN XP SP3硬编码
	pList_Current = ( PLIST_ENTRY )( * ( ULONG* )( ( ULONG ) Eprocess + 0xc4 ) + 0x1c );
	if( pList_Current != NULL )
	{
		if (pList_Current->Blink && pList_Current->Blink->Flink )
		{
			g_OwnInfo.pHandleBlink = pList_Current->Blink;
			pList_Current->Blink->Flink = pList_Current->Flink;
		}

		if (pList_Current->Flink && pList_Current->Flink->Blink )
		{
			g_OwnInfo.pHandleFlink = pList_Current->Flink;
			pList_Current->Flink->Blink = pList_Current->Blink;
		}

		pList_Current->Flink = NULL;
		pList_Current->Blink = NULL;
	}
	return;
}
//
//
//
/*
// 遍历句柄表回调函数
// HandleTableEntry	: A pointer to the top level handle table tree node.
// Handle			: 本次遍历到的HANDLE 索引值
// EnumParameter	: 每次遍历到一个可用HANDLE,就会传递程序员指定的32BIT值的地址
*/
BOOL EnumTableCallBack(
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN OUT PVOID EnumParameter )
{

	PVOID Temp = NULL;

	if( cid.EnumCallBackHideType == FALSE )
	{
		//
		// 遍历到要隐藏的句柄
		//
		if( ARGUMENT_PRESENT( EnumParameter ) && * ( ( HANDLE* ) EnumParameter ) == Handle )
		{
			avPrint( "find handle!") ;

			* ( PHANDLE_TABLE_ENTRY* ) EnumParameter = HandleTableEntry;

			return TRUE;
		}
		else
		{
			return FALSE;
		}
	}
	else if( cid.EnumCallBackHideType == TRUE)
	{
		//
		// 遍历的是csrss进程句柄表
		//
		//Temp = HandleTableEntry->Object;

		////
		//// 遍历到要隐藏的句柄
		////
		//if( ARGUMENT_PRESENT( EnumParameter ) && Temp == EnumCallBackHideObject )
		//{
		//	avPrint( "Get Csrss EraseHandle!");

		//	* ( PHANDLE_TABLE_ENTRY* ) EnumParameter = HandleTableEntry;
		//	return TRUE;
		//}
		//else
		//{
		//	return FALSE;
		//}
		return FALSE;
	}
	else
	{
		return FALSE;
	}
}

//
// 擦除某个Eprocess句柄表中指定的进程ID句柄
//

NTSTATUS EraseObjectFromTable( IN PHANDLE_TABLE HandleTable, IN HANDLE ProcessId )
{
	NTSTATUS Status = STATUS_NOT_FOUND;
	PVOID EnumParameter = NULL;
	UNICODE_STRING uExEnumHandleTable = {0};
	PExEnumHandleTable ExEnumHandleTable;

	Status = STATUS_NOT_FOUND;

	EnumParameter = (PVOID)ProcessId;

	RtlInitUnicodeString( &uExEnumHandleTable, L"ExEnumHandleTable" );
	ExEnumHandleTable = (PExEnumHandleTable)MmGetSystemRoutineAddress( &uExEnumHandleTable );

	if( NULL == ExEnumHandleTable )
	{
		avPrint( "Get ExEnumHandleTable Address Error!" );
		return Status;
	}

	//
	// 如果找到
	//
	if( ExEnumHandleTable( HandleTable, EnumTableCallBack, &EnumParameter, NULL ) )
	{
		//
		// 擦除句柄
		//
		//擦除之前先记录一下，只记录PSP表中的
		if (cid.EnumCallBackHideType == FALSE)
		{
			cid.PspHideCidTableEntry = (PHANDLE_TABLE_ENTRY)EnumParameter;
			cid.HidePspObject = cid.PspHideCidTableEntry->Object;
		}
		InterlockedExchangePointer( & ( ( PHANDLE_TABLE_ENTRY ) EnumParameter )->Object, NULL );

		avPrint( "Call EraseObjectFromTable Success!" );

		Status = STATUS_SUCCESS;
	}

	return Status;
}
//
NTSTATUS ErasePspTable(HANDLE dwHidePid)
{
	//CodeVprint( "开始擦除PspCidTable句柄表进程句柄\n" );
	PHANDLE_TABLE pPspCidTableAddr = NULL;
	if(STATUS_SUCCESS != GetPspCidTable(&pPspCidTableAddr))
	{
		return STATUS_UNSUCCESSFUL;
	}
	cid.EnumCallBackHideType = FALSE;
	// EraseObjectFromTable( * ( PULONG ) pPspHandleAddr, dwHidePid );
	return EraseObjectFromTable(pPspCidTableAddr,dwHidePid);
}
//

//恢复PSPtable
VOID RecoverPspTable()
{
	if (cid.PspHideCidTableEntry != NULL)
	{
		InterlockedExchangePointer( &((cid.PspHideCidTableEntry)->Object), cid.HidePspObject );
	}
}

VOID RecoverHideProcess()
{
	/*PLIST_ENTRY pCurrent = ( PLIST_ENTRY )( ( ULONG ) g_OwnInfo.pProtectedProcess + 0x88 );
	if (g_OwnInfo.pActiveBlink)
	{
		g_OwnInfo.pActiveBlink->Flink = 
			pCurrent;
	}
	if (g_OwnInfo.pActiveFlink)
	{
		g_OwnInfo.pActiveFlink->Blink = 
			pCurrent;
	}
	pCurrent->Blink = g_OwnInfo.pActiveBlink;
	pCurrent->Flink = g_OwnInfo.pActiveFlink;
	pCurrent = ( PLIST_ENTRY )( ( ULONG ) g_OwnInfo.pProtectedProcess + 0x0b4 );
	if (g_OwnInfo.pSessionBlink)
	{
		g_OwnInfo.pSessionBlink->Flink = pCurrent;
	}
	if (g_OwnInfo.pSessionFlink)
	{
		g_OwnInfo.pSessionFlink->Blink = pCurrent;
	}
	pCurrent->Blink = g_OwnInfo.pSessionBlink;
	pCurrent->Flink = g_OwnInfo.pSessionFlink;

	 WIN XP SP3硬编码
	pCurrent = ( PLIST_ENTRY )( * ( ULONG* )( ( ULONG ) g_OwnInfo.pProtectedProcess + 0xc4 ) + 0x1c );
	if (g_OwnInfo.pHandleBlink)
	{
		g_OwnInfo.pHandleBlink->Flink = pCurrent;
	}
	if (g_OwnInfo.pHandleFlink)
	{
		g_OwnInfo.pHandleFlink->Blink = pCurrent;
	}
	pCurrent->Blink = g_OwnInfo.pHandleBlink;
	pCurrent->Flink = g_OwnInfo.pHandleFlink;
*/


}
VOID HideOwnProcess()
{
	//RemoveFromProcessLinks(g_OwnInfo.pProtectedProcess);
	//RemoveFromHandleTableList(g_OwnInfo.pProtectedProcess);
	//ErasePspTable((HANDLE)g_OwnInfo.dwPid);
}