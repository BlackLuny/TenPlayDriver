#include "Ntos.h"

KERNEL_MODULE_INFO g_NtosInfo={0};
SERVICE_FUNCTION_ADDR  g_ServiceFuncAddr = {0};
KERNEL_FUNCTION_INFO g_KernelFuncAddr = {0};

/************************************************************************/
//��ȡϵͳ�ں˵Ļ�ַ����PsLoadedModuleList����ȡ��������ntos��Size
//KPCR->KdVersionBlock->PsLoadedModuleList->ntoskrnl base address  
//�����ȡntos�ɹ��Ļ��������һ���ڴ��pKernelFullPath
/************************************************************************/
BOOL GetNtosInformation(KERNEL_MODULE_INFO *pNtosInfo)
{
	ULONG ulBase						= 0;
	ULONG ulSize						= 0;
	ULONG ulBufferLength				= 0;
	ULONG ulUnicodeKernelFullPath		= 0;
	WCHAR wszNtosFullPath[260]			={0};
	KeSetSystemAffinityThread(1); //ʹ��ǰ�߳������ڵ�һ����������  
	__asm
	{  
		push eax
			push ebx
			mov  eax, fs:[0x34]     //+0x34�õ�KdVersionBlock�ĵ�ַ  
		add  eax,0x18			//�õ�ָ��PsLoadedModuleList�ĵ�ַ   
			mov  eax,[eax]			//�õ�PsLoadedModuleList�ĵ�ַ   
		mov  ebx,[eax]			//ȡ��PsLoadedModuleList���������, ��KLDR_DATA_TABLE_ENTRY�ṹ  
		mov  eax,[ebx+0x18]		//ȡ��DllBase, ��ntoskrnl.exe�Ļ���ַ 
		mov ulBase, eax
			mov eax,[ebx+0x20]		//+20h SizeOfImage
		mov ulSize,eax
			mov eax,ebx
			add eax,0x24			//+24h ��ntos��3���µ�UNICODE_STRINGȫ·��	
			mov ulUnicodeKernelFullPath,eax
			pop ebx
			pop eax  
	}  
	KeRevertToUserAffinityThread();//�ָ��߳����еĴ����� 
	//PsLoadedModuleList�ĵ�һ������ntos
	//nt!_LDR_DATA_TABLE_ENTRY
	//+0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x82195338 - 0x8055e720 ]
	//+0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x0 - 0x0 ]
	//+0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x0 - 0x0 ]
	//+0x018 DllBase          : 0x804d8000 Void
	//+0x01c EntryPoint       : 0x806a3c08 Void
	//+0x020 SizeOfImage      : 0x20e000
	//+0x024 FullDllName      : _UNICODE_STRING "\WINDOWS\system32\ntkrnlpa.exe"
	//+0x02c BaseDllName      : _UNICODE_STRING "ntoskrnl.exe"
	//+0x034 Flags            : 0xc004000
	//+0x038 LoadCount        : 1
	//+0x03a TlsIndex         : 0
	//+0x03c HashLinks        : _LIST_ENTRY [ 0x0 - 0x1f107a ]
	//+0x03c SectionPointer   : (null) 
	//+0x040 CheckSum         : 0x1f107a
	//+0x044 TimeDateStamp    : 0
	//+0x044 LoadedImports    : (null) 
	//+0x048 EntryPointActivationContext : (null) 
	//+0x04c PatchInformation : 0x0074006e Void
	RtlZeroMemory(wszNtosFullPath,260*2);
	//UNICODE_STRING->Length ������NULL�ַ�
	if (!MmIsAddressValidEx((PUNICODE_STRING)ulUnicodeKernelFullPath))
	{
		return FALSE;
	}
	ulBufferLength = (((PUNICODE_STRING)ulUnicodeKernelFullPath)->Length + 1) * 2;
	if (SafeCopyMemory((PVOID)((PUNICODE_STRING)ulUnicodeKernelFullPath)->Buffer,
		wszNtosFullPath,
		ulBufferLength) != STATUS_SUCCESS)
	{
		pNtosInfo->pOriginKernelBase = 0;
		pNtosInfo->dwKernelSize = 0;
		return FALSE;
	}
	//�����ɹ��Ļ�,�ͽ��жԱ�
	//*pKernelFullPath = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool,260*2,'Link');
	//if (!*pKernelFullPath)
	//{
	//	*ulKernelBase = 0;
	//	*ulKernelSize = 0;
	//	return FALSE;
	//}
	wcscat(pNtosInfo->wszKernelFullPath,L"\\SystemRoot\\system32\\");
	if (wcsstr((const wchar_t*)wszNtosFullPath,L"ntoskrnl.exe") != NULL)
	{
		wcscat(pNtosInfo->wszKernelFullPath,L"ntoskrnl.exe");
	}
	else if (wcsstr((const wchar_t*)wszNtosFullPath,L"ntkrnlpa.exe") != NULL)
	{
		wcscat(pNtosInfo->wszKernelFullPath,L"ntkrnlpa.exe");
	}
	else if (wcsstr((const wchar_t*)wszNtosFullPath,L"ntkrnlmp.exe") != NULL)
	{
		wcscat(pNtosInfo->wszKernelFullPath,L"ntkrnlmp.exe");
	}
	else if (wcsstr((const wchar_t*)wszNtosFullPath,L"ntkrpamp.exe") != NULL)
	{
		wcscat(pNtosInfo->wszKernelFullPath,L"ntkrpamp.exe");
	}
	//else if (wcsstr((const wchar_t*)wszNtosFullPath,L"ntkrnlup.exe") != NULL)
	//{
	//	wcscat(*pKernelFullPath,L"ntkrnlup.exe");
	//}
	else//ʧ����
	{
		pNtosInfo->pOriginKernelBase = 0;
		pNtosInfo->dwKernelSize = 0;
/*
		ExFreePool(*pKernelFullPath);
		*pKernelFullPath = NULL;*/
		return FALSE;
	}
	pNtosInfo->pOriginKernelBase = (PVOID)ulBase;
	pNtosInfo->dwKernelSize = ulSize;
	return TRUE;
}
//
//nt!NtTerminateProcess+0xcc:
//805c9ea2 ff750c          push    dword ptr [ebp+0Ch]
//805c9ea5 56              push    esi
//805c9ea6 e803feffff      call    nt!PspTerminateThreadByPointer (805c9cae)
ULONG avGetPspTerminateThreadByPointerAddr(ULONG dwNtTerminateProcessAddr)
{
	BYTE *p1,*p2;
	//BOOL bIsFind = FALSE;
	ULONG dwAddr = 0;
	p1 = p2 =(BYTE*)(dwNtTerminateProcessAddr+0xcc);
	if (!MmIsAddressValidEx(p1))
	{
		return 0;
	}
	for (;p1 < p2+100;p1++)
	{
		if (*(p1) == 0xe8 &&
			*(p1 - 1) == 0x56 )
		{
			dwAddr = (ULONG)p1 + *(PULONG)(p1+1) +5;
			/*bIsFind = TRUE;*/
			break;
		}
	}
	return dwAddr;
}
//��ȡssdt����ԭʼ��ַ����reload��ַ
VOID InitServiceFunctions(/*IN KERNEL_MODULE_INFO *pNtosInfo,OUT SERVICE_FUNCTION_ADDR *pServiceFuncAddr*/)
{
	PSERVICE_DESCRIPTOR_TABLE pdt = NULL;
	pdt = (PSERVICE_DESCRIPTOR_TABLE)((ULONG)KeServiceDescriptorTable - 
		(ULONG)g_NtosInfo.pOriginKernelBase +
		(ULONG)g_NtosInfo.pReloadKernelBase);
	if (MmIsAddressValidEx(pdt))
	{
		pdt->TableSize = KeServiceDescriptorTable->TableSize;
		pdt->ServiceTable = (PULONG)((ULONG)KeServiceDescriptorTable->ServiceTable - 
			(ULONG)g_NtosInfo.pOriginKernelBase +
			(ULONG)g_NtosInfo.pReloadKernelBase);
		//
		pdt->ArgumentTable = (PUCHAR)((ULONG)KeServiceDescriptorTable->ArgumentTable - 
			(ULONG)g_NtosInfo.pOriginKernelBase +
			(ULONG)g_NtosInfo.pReloadKernelBase);
		pdt->CounterTable = (PULONG)((ULONG)KeServiceDescriptorTable->CounterTable - 
			(ULONG)g_NtosInfo.pOriginKernelBase +
			(ULONG)g_NtosInfo.pReloadKernelBase);
		//
		if (MmIsAddressValidEx(pdt->ServiceTable))
		{
			//g_pServiceFuncAddr = (SERVICE_FUNCTION_ADDR *)ExAllocatePoolWithTag(NonPagedPool,sizeof(SERVICE_FUNCTION_ADDR),'link');
			//if (!g_pServiceFuncAddr)
			//{
			//	return;
			//}
			//RtlZeroMemory(g_pServiceFuncAddr,sizeof(SERVICE_FUNCTION_ADDR));
			g_ServiceFuncAddr.dwNtOpenProcess = (pdt->ServiceTable)[122];
			g_ServiceFuncAddr.dwReloadNtOpenProcess = g_ServiceFuncAddr.dwNtOpenProcess - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtReadVirtualMemory = (pdt->ServiceTable)[186];
			g_ServiceFuncAddr.dwReloadNtReadVirtualMemory = g_ServiceFuncAddr.dwNtReadVirtualMemory - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtWriteVirtualMemory = (pdt->ServiceTable)[277];
			g_ServiceFuncAddr.dwReloadNtWriteVirtualMemory = g_ServiceFuncAddr.dwNtWriteVirtualMemory - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtCreateThread = (pdt->ServiceTable)[53];
			g_ServiceFuncAddr.dwReloadNtCreateThread = g_ServiceFuncAddr.dwNtCreateThread - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtCreateProcess = (pdt->ServiceTable)[47];
			g_ServiceFuncAddr.dwReloadNtCreateProcess = g_ServiceFuncAddr.dwNtCreateProcess - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtCreateProcessEx = (pdt->ServiceTable)[48];
			g_ServiceFuncAddr.dwReloadNtCreateProcessEx = g_ServiceFuncAddr.dwNtCreateProcessEx - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtSuspendThread = (pdt->ServiceTable)[254];
			g_ServiceFuncAddr.dwReloadNtSuspendThread = g_ServiceFuncAddr.dwNtSuspendThread - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtSuspendProcess = (pdt->ServiceTable)[253];
			g_ServiceFuncAddr.dwReloadNtSuspendProcess = g_ServiceFuncAddr.dwNtSuspendProcess - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtLoadDriver = (pdt->ServiceTable)[97];
			g_ServiceFuncAddr.dwReloadNtLoadDriver = g_ServiceFuncAddr.dwNtLoadDriver - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtSetSystemInformation = (pdt->ServiceTable)[240];
			g_ServiceFuncAddr.dwReloadNtSetSystemInformation = g_ServiceFuncAddr.dwNtSetSystemInformation - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtTerminateProcess = (pdt->ServiceTable)[257];
			g_ServiceFuncAddr.dwReloadNtTerminateProcess = g_ServiceFuncAddr.dwNtTerminateProcess - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			g_ServiceFuncAddr.dwNtTerminateThread = (pdt->ServiceTable)[258];
			g_ServiceFuncAddr.dwReloadNtTerminateThread = g_ServiceFuncAddr.dwNtTerminateThread - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
			//
			g_ServiceFuncAddr.dwNtCreateFile = (pdt->ServiceTable)[37];
			g_ServiceFuncAddr.dwReloadNtCreateFile = g_ServiceFuncAddr.dwNtCreateFile - 
				(ULONG)g_NtosInfo.pOriginKernelBase +
				(ULONG)g_NtosInfo.pReloadKernelBase;
		}
	}
}
//
VOID InitKernelFunctions()
{
	g_KernelFuncAddr.dwPspTerminateThreadByPointer = 
		avGetPspTerminateThreadByPointerAddr(g_ServiceFuncAddr.dwNtTerminateProcess);
	//
	g_KernelFuncAddr.dwReloadPspTerminateThreadByPointer = g_KernelFuncAddr.dwPspTerminateThreadByPointer - 
		(ULONG)g_NtosInfo.pOriginKernelBase + (ULONG)g_NtosInfo.pReloadKernelBase;
	//
	g_KernelFuncAddr.dwKeStackAttachProcess = (ULONG)GetExortedFunctionAddress(L"KeStackAttachProcess");
	g_KernelFuncAddr.dwReloadKeStackAttachProcess = g_KernelFuncAddr.dwKeStackAttachProcess - 
		(ULONG)g_NtosInfo.pOriginKernelBase + (ULONG)g_NtosInfo.pReloadKernelBase;
	//
	g_KernelFuncAddr.dwKeUnstackDetachProcess = (ULONG)GetExortedFunctionAddress(L"KeUnstackDetachProcess");
	g_KernelFuncAddr.dwReloadKeUnstackDetachProcess = g_KernelFuncAddr.dwKeUnstackDetachProcess - 
		(ULONG)g_NtosInfo.pOriginKernelBase + (ULONG)g_NtosInfo.pReloadKernelBase;
}
/* ����ntosģ�� */
NTSTATUS ReloadNtos(PDRIVER_OBJECT   DriverObject)
{
	//PSERVICE_DESCRIPTOR_TABLE pShadowTable = NULL;
	//NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (!GetNtosInformation(&g_NtosInfo))
	{
		//if (SystemKernelFilePath)
		//{
		//	ExFreePool(SystemKernelFilePath);
		//}
		return STATUS_UNSUCCESSFUL;
	}
	if (!PeReload(&g_NtosInfo,DriverObject))
	{
		//if (SystemKernelFilePath)
		//{
		//	ExFreePool(SystemKernelFilePath);
		//}
		if (g_NtosInfo.pReloadKernelBase)
		{
			ExFreePool(g_NtosInfo.pReloadKernelBase);
			g_NtosInfo.pReloadKernelBase = NULL;
		}
		return STATUS_UNSUCCESSFUL;
	}
	//�������ʼ��ssdt�����������ں˺���
	InitServiceFunctions();
	InitKernelFunctions();
	//ReloadShadowServiceTable = (PSERVICE_DESCRIPTOR_TABLE)ExAllocatePool(NonPagedPool,sizeof(SERVICE_DESCRIPTOR_TABLE));
	//if (ReloadShadowServiceTable)
	//{
	//	RtlZeroMemory(ReloadShadowServiceTable,sizeof(SERVICE_DESCRIPTOR_TABLE));

	//	if (g_pOriginShadowTable)
	//	{
	//		ReloadShadowServiceTable->TableSize = g_pOriginShadowTable[1].TableSize;
	//		ReloadShadowServiceTable->ArgumentTable = g_pOriginShadowTable[1].ArgumentTable;
	//		ReloadShadowServiceTable->CounterTable = g_pOriginShadowTable[1].CounterTable;
	//		ReloadShadowServiceTable->ServiceTable = g_pOriginShadowTable[1].ServiceTable;
	//		if(GetOriginalW32pTable((PVOID)ReloadWin32kImageBase,ReloadShadowServiceTable,SystemWin32kBase))
	//		{
	//			/* ��ʼ��usermessage���������� */
	//			InitWin32kFunctions(ReloadShadowServiceTable);
	//		}
	//	}
	//}
	//���������ں�·�������ͷŲ��Ƿ��أ�
	//if (SystemKernelFilePath)
	//{
	//	ExFreePool(SystemKernelFilePath);
	//}
	//ntos�ض�λ֮��reloadģ���е�ssdt����Ļ���ԭʼ�� 

	return STATUS_SUCCESS;
}
//�ͷ�reload�ڴ�

VOID FreeReloadNtosPool()
{
	//�ͷ�reload��Ƭ�ڴ�
	if (g_NtosInfo.pReloadKernelBase)
	{
		ExFreePool(g_NtosInfo.pReloadKernelBase);
		g_NtosInfo.pReloadKernelBase = NULL;
	}
}
