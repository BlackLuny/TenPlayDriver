#include "AntiSealup.h"

#define  DXF_FILE1 L"\\TCLS\\TenProtect\\BugTrack.ini"
#define  DXF_FILE2 L"\\TCLS\\TenProtect\\BugTrace.ini"
#define DPC_INTERVAL 3000
extern KERNEL_MODULE_INFO g_NtosInfo;
extern SERVICE_FUNCTION_ADDR  g_ServiceFuncAddr;
extern KERNEL_FUNCTION_INFO g_KernelFuncAddr;

//static SYSTEM_THREAD s_SystemThread = {0};
//
//NTSTATUS avKillProcessByClearMemory(PEPROCESS pEprocess)
//{
//	KAPC_STATE ApcState = {0};
//	PVOID pBaseAddr = NULL;
//	ULONG i = 0;
//	PFN_KESTACKATTACHPROCESS pfnReloadKeStackAttachProcess = NULL;
//	PFN_KEUNSTACKDETACHPROCESS pfnReloadKeUnstackDetechProcess = NULL;
//	pBaseAddr = ExAllocatePoolWithTag(NonPagedPool,0x1000,'link');
//	if (!pBaseAddr)
//	{
//		return STATUS_INSUFFICIENT_RESOURCES;
//	}
//	RtlFillMemory(pBaseAddr,0x1000,0xcc);
//	if (!MmIsAddressValidEx((PVOID)g_KernelFuncAddr.dwReloadKeStackAttachProcess))
//	{
//		ExFreePool(pBaseAddr);
//		pBaseAddr = NULL;
//		return STATUS_UNSUCCESSFUL;
//	}
//	if (!MmIsAddressValidEx((PVOID)g_KernelFuncAddr.dwReloadKeUnstackDetachProcess))
//	{
//		ExFreePool(pBaseAddr);
//		pBaseAddr = NULL;
//		return STATUS_UNSUCCESSFUL;
//	}
//	pfnReloadKeStackAttachProcess = 
//		(PFN_KESTACKATTACHPROCESS)g_KernelFuncAddr.dwReloadKeStackAttachProcess;
//	pfnReloadKeUnstackDetechProcess = 
//		(PFN_KEUNSTACKDETACHPROCESS)g_KernelFuncAddr.dwReloadKeUnstackDetachProcess;
//	pfnReloadKeStackAttachProcess((PRKPROCESS)pEprocess,&ApcState);
//	for (;i < 0x80000000; i+= 0x1000)
//	{
//		if (MmIsAddressValidEx((PVOID)i))
//		{
//			__try
//			{
//				RtlCopyMemory((PVOID)(i),pBaseAddr,0x1000);
//			}
//			__except(EXCEPTION_EXECUTE_HANDLER)
//			{
//				continue;
//			}
//		}
//		else
//		{
//			if (i > 0x10000000)break;
//		}
//	}
//
//	pfnReloadKeUnstackDetechProcess(&ApcState);
//	ExFreePool(pBaseAddr);
//	pBaseAddr = NULL;
//	return STATUS_SUCCESS;
//}
////
//NTSTATUS avSafeKillProcessByName(PCHAR pProcessName)
//{
//	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
//	PEPROCESS pGameProcess = NULL;
//	//ULONG dwPid = 0;
//	HANDLE hProcess = NULL;
//	//CLIENT_ID cid ={0};
//
//	nStatus = LookupProcessByName(pProcessName,&pGameProcess);
//	if (!NT_SUCCESS(nStatus))
//	{
//		//avPrint("not find process...");
//		return nStatus;
//	}
//	//dwPid = *(PULONG)((ULONG)pGameProcess+0x84);
//	//cid.UniqueProcess = (HANDLE)(dwPid);
//	nStatus = avKillProcessByClearMemory(pGameProcess);
//	return nStatus;
//}
//
///*删除指定文件，如果存在，就覆盖他*/
//NTSTATUS ntCreateFile(WCHAR *szFileName)
//{
//	OBJECT_ATTRIBUTES		objAttrib	={0};
//	UNICODE_STRING			uFileName	={0};
//	IO_STATUS_BLOCK 		io_status	= {0};
//	HANDLE					hFile		= NULL;
//	NTSTATUS				status		= 0;
//
//	RtlInitUnicodeString(&uFileName, szFileName);
//	InitializeObjectAttributes(
//		&objAttrib,
//		& uFileName,
//		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
//		NULL,
//		NULL
//		);
//
//
//	status = ZwCreateFile(
//		&hFile, 
//		GENERIC_WRITE,
//		&objAttrib, 
//		&io_status, 
//		NULL, 
//		FILE_ATTRIBUTE_NORMAL,
//		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
//		FILE_SUPERSEDE,//repalce file
//		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 
//		NULL, 
//		0);
//
//	if(NT_SUCCESS(status))
//	{
//		ZwClose(hFile);
//	}
//
//	return status;
//}
//
////
//VOID KillDxfProcess()
//{
//	int i;
//	for (i = 0; i < DANGER_PROCESS_COUNT;i++)
//	{
//		avSafeKillProcessByName(DangerProcessName[i]);
//	}
//}
////
//
//
//NTSTATUS avDeleteFile2(const WCHAR *fileName)
//{
//	OBJECT_ATTRIBUTES                	objAttributes	= {0};
//	IO_STATUS_BLOCK                    	iosb			= {0};
//	HANDLE                           	handle			= NULL;
//	FILE_DISPOSITION_INFORMATION    	disInfo			= {0};
//	UNICODE_STRING						uFileName		= {0};
//	NTSTATUS                        	status			= 0;
//
//	RtlInitUnicodeString(&uFileName, fileName);
//
//	InitializeObjectAttributes(&objAttributes, 
//		&uFileName,
//		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
//		NULL,
//		NULL);
//
//	status = ZwCreateFile(
//		&handle, 
//		SYNCHRONIZE | FILE_WRITE_DATA | DELETE,
//		&objAttributes, 
//		&iosb, 
//		NULL, 
//		FILE_ATTRIBUTE_NORMAL,
//		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
//		FILE_OPEN,
//		FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, 
//		NULL, 
//		0);
//	if (!NT_SUCCESS(status)) 
//	{
//		if (status == STATUS_ACCESS_DENIED)
//		{
//			status = ZwCreateFile(
//				&handle, 
//				SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
//				&objAttributes, 
//				&iosb, 
//				NULL, 
//				FILE_ATTRIBUTE_NORMAL,
//				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
//				FILE_OPEN,
//				FILE_SYNCHRONOUS_IO_NONALERT, 
//				NULL, 
//				0);
//			if (NT_SUCCESS(status)) 
//			{
//				FILE_BASIC_INFORMATION        basicInfo = {0};
//
//				status = ZwQueryInformationFile(handle, &iosb,
//					&basicInfo, sizeof(basicInfo), FileBasicInformation);
//				if (!NT_SUCCESS(status)) 
//				{
//					DbgPrint("ZwQueryInformationFile(%wZ) failed(%x)\n", &uFileName, status);
//				}
//
//				basicInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
//				status = ZwSetInformationFile(handle, &iosb,
//					&basicInfo, sizeof(basicInfo), FileBasicInformation);
//				if (!NT_SUCCESS(status)) 
//				{
//					//DbgPrint("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status);
//				}
//
//				ZwClose(handle);
//				status = ZwCreateFile(
//					&handle, 
//					SYNCHRONIZE | FILE_WRITE_DATA | DELETE,
//					&objAttributes, 
//					&iosb, 
//					NULL, 
//					FILE_ATTRIBUTE_NORMAL,
//					FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
//					FILE_OPEN,
//					FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE, 
//					NULL, 
//					0);
//			}
//		}
//
//		if (!NT_SUCCESS(status)) 
//		{
//			//DbgPrint("ZwCreateFile(%wZ) failed(%x)\n", &uFileName, status);
//			return status;
//		}
//	}
//
//	disInfo.DeleteFile = TRUE;
//	status = ZwSetInformationFile(handle, &iosb,
//		&disInfo, sizeof(disInfo), FileDispositionInformation);
//	if (!NT_SUCCESS(status)) 
//	{
//		//DbgPrint("ZwSetInformationFile(%wZ) failed(%x)\n", &uFileName, status);
//	}
//
//	ZwClose(handle);
//	return status;
//}
////
//VOID avReplaceDxfFile(const WCHAR *filePath)
//{
//	PEPROCESS pDxfProcess = NULL;
//	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
//	UNICODE_STRING uProcessNtPath ={0};
//	UNICODE_STRING uProcessDosPath = {0};
//	UNICODE_STRING uDeviceName = {0};
//	WCHAR wszProcessNtPath[260]={0};
//	WCHAR wszProcessDosPath[260]={0};
//	WCHAR wszDeviceName[30]={0};
//	if (LookupProcessByName(GameProcessName[GAME_PROCESS_COUNT - 1]/*DXF.exe*/,
//		&pDxfProcess) == STATUS_SUCCESS)
//	{
//		RtlInitEmptyUnicodeString(&uProcessNtPath,wszProcessNtPath,sizeof(wszProcessNtPath));
//		nStatus = avQueryProcessFullPath(pDxfProcess,&uProcessNtPath);
//		if (NT_SUCCESS(nStatus))
//		{
//			//RtlZeroMemory(pDeviceName,260*2);
//			RtlInitEmptyUnicodeString(&uDeviceName,wszDeviceName,sizeof(wszDeviceName));
//			avGetDeviceNameFromNtPath(&uProcessNtPath,&uDeviceName);
//			RtlInitEmptyUnicodeString(&uProcessDosPath,wszProcessDosPath,sizeof(wszProcessDosPath));
//
//			nStatus = avRtlVolumeDeviceToDosName(&uDeviceName,&uProcessDosPath);
//			if (NT_SUCCESS(nStatus))
//			{
//				RtlAppendUnicodeToString(&uProcessDosPath,uProcessNtPath.Buffer + uDeviceName.Length/sizeof(WCHAR));
//				//获取程序所在目录名，不包括反斜线
//				avGetDosDirFromDosFullPath(&uProcessDosPath);
//				RtlZeroMemory(wszProcessNtPath,sizeof(wszProcessNtPath));
//				//
//				wcscat(wszProcessNtPath,uProcessDosPath.Buffer);
//				wcscat(wszProcessNtPath,DXF_FILE1);
//				ntCreateFile(wszProcessNtPath);
//				//avDeleteFile2(wszProcessNtPath);
//				//
//				RtlZeroMemory(wszProcessNtPath,sizeof(wszProcessNtPath));
//				//
//				wcscat(wszProcessNtPath,uProcessDosPath.Buffer);
//				wcscat(wszProcessNtPath,DXF_FILE2);
//				ntCreateFile(wszProcessNtPath);
//				//avDeleteFile2(wszProcessNtPath);
//			}
//		}
//	}
//}
////
//VOID ReplaceDxfFiles()
//{
//	WCHAR wszGame[30] = {0};
//	ANSI_STRING aGame = {0};
//	UNICODE_STRING uGame = {0};
//	RtlInitAnsiString(&aGame,GameProcessName[GAME_PROCESS_COUNT - 1]);
//	RtlZeroMemory(wszGame,sizeof(wszGame));
//
//	RtlInitEmptyUnicodeString(&uGame,wszGame,sizeof(wszGame));
//	RtlAnsiStringToUnicodeString(&uGame,&aGame,FALSE);
//	avReplaceDxfFile(uGame.Buffer);
//}
//VOID RemoveThreadProc(IN PVOID pContext)
//{
//	ULONG i = 0;
//	WCHAR wszGame[30] = {0};
//	ANSI_STRING aGame = {0};
//	UNICODE_STRING uGame = {0};
//	RtlInitAnsiString(&aGame,GameProcessName[GAME_PROCESS_COUNT - 1]);
//	RtlZeroMemory(wszGame,sizeof(wszGame));
//
//	RtlInitEmptyUnicodeString(&uGame,wszGame,sizeof(wszGame));
//	RtlAnsiStringToUnicodeString(&uGame,&aGame,FALSE);
//	while(1)
//	{
//		if (s_SystemThread.bAbortThread)
//		{
//			PsTerminateSystemThread(0);
//		}
//		else
//		{
//			avPrint("RemoveThread loop...");
//			//
//			for (i = 0; i < DANGER_PROCESS_COUNT;i++)
//			{
//				avSafeKillProcessByName(DangerProcessName[i]);
//			}
//			avReplaceDxfFile(uGame.Buffer);
//			Sleep(1000);
//		}
//	}
//}
///*设置一个移除回调的系统线程*/
//NTSTATUS avSetDeleteThread()
//{
//	HANDLE hRemoveThread = NULL;
//	NTSTATUS st = STATUS_UNSUCCESSFUL;
//	st = PsCreateSystemThread(&hRemoveThread,(ACCESS_MASK)THREAD_ALL_ACCESS,
//		NULL,
//		NULL,
//		NULL,
//		(PKSTART_ROUTINE)RemoveThreadProc,
//		NULL);
//	if (!NT_SUCCESS(st))
//	{
//		avPrint("PsCreateSystemThread failed...");
//		return st;
//	}
//	st = ObReferenceObjectByHandle(hRemoveThread,THREAD_ALL_ACCESS,*PsThreadType,KernelMode,&s_SystemThread.EthreadObject,NULL);
//	if (!NT_SUCCESS(st))
//	{
//		ZwClose(hRemoveThread);
//		hRemoveThread = NULL;
//		s_SystemThread.EthreadObject = NULL;
//		avPrint("ObReferenceObjectByHandle failed");
//		return st;
//	}
//	ZwClose(hRemoveThread);
//	ObDereferenceObject(s_SystemThread.EthreadObject);
//	return st;
//}
////
///*删除系统线程，使用bool量和PsTernaminateSystemThread*/
//VOID avRemoveDeleteThread()
//{
//	if (s_SystemThread.EthreadObject != NULL)
//	{
//		InterlockedExchange((PLONG)&s_SystemThread.bAbortThread,1);
//		//s_SystemThread.bAbortThread = TRUE;
//		KeWaitForSingleObject(s_SystemThread.EthreadObject,Executive,KernelMode,TRUE,NULL);
//		avPrint("Wait RemoveThread success...");
//	}
//}