#include "HookPort.h"

//LONG g_nHookPortRefCnt = {0};

LONG g_HookReferCnt[MAX_REFER_CNT] ={0};
static BOOL s_bIsHookSuccessed = FALSE;
static INLINE_HOOK_INFO s_HookInfo={0};
//static INLINE_HOOK_INFO s_OriFastCall={0};
//保存被hook的code
static BYTE s_byHookCode[5]={0};
static CONST WCHAR wszRegeditPath[260] =L"\\??\\C:\\windows\\regedit.exe";
//////////////////////////////////////////////////////////////////////////
extern SERVICE_FUNCTION_ADDR g_ServiceFuncAddr;
extern OWNPROCESS_INFO g_OwnInfo;
extern KERNEL_MODULE_INFO g_NtosInfo;
extern WCHAR wOwnProcessName[30];
extern WCHAR wOwnDmDll[30];

NTSTATUS
	__stdcall
	NewNtOpenProcess (
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID ClientId
	)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	PEPROCESS eprocess_debugger = NULL;
	PEPROCESS eprocess_ctfmon = NULL;
	HANDLE CsrId = (HANDLE)0;
	PFN_NTOPENPROCESS pfnNtOpenProcess;
	//
	InterlockedIncrement(&g_HookReferCnt[0]);
	pfnNtOpenProcess=(PFN_NTOPENPROCESS)g_ServiceFuncAddr.dwNtOpenProcess;
	if (PsGetCurrentProcess() == g_OwnInfo.pProtectedProcess)
	{
		pfnNtOpenProcess = (PFN_NTOPENPROCESS)g_ServiceFuncAddr.dwReloadNtOpenProcess;
		goto _CleanUp;
	}

	if (IsFromGameProcess())
	{
		//CodeVprint("tp is  calling NtOpenProcess\r\n");
		if (MmIsAddressValidEx(ClientId))
		{
			if (ClientId->UniqueProcess)
			{
				if ((ULONG)(ClientId->UniqueProcess) == g_OwnInfo.dwPid)
				{
					/* 把我们的进程id改为csrss的id */
					avPrint("TP is detecting our process...");
					//CsrId = GetCsrPid();
					ClientId->UniqueProcess = (HANDLE)4;
				}
			}
		}
	}
_CleanUp:
	nStatus = pfnNtOpenProcess(ProcessHandle,
		DesiredAccess,
		ObjectAttributes,
		ClientId);
	InterlockedDecrement(&g_HookReferCnt[0]);
	return nStatus;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS
	__stdcall
	NewNtReadVirtualMemory (
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__out_bcount(BufferSize) PVOID Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesRead
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	//NTREADVIRTUALMEMORY pfnNtReadVirtualMemory;
	InterlockedIncrement(&g_HookReferCnt[1]);
	//pfnNtReadVirtualMemory = (NTREADVIRTUALMEMORY)g_ServiceFuncAddr.dwNtReadVirtualMemory;
	if (PsGetCurrentProcess() == g_OwnInfo.pProtectedProcess)
	{
		nStatus = ((NTREADVIRTUALMEMORY)g_ServiceFuncAddr.dwReloadNtReadVirtualMemory)(ProcessHandle,
			BaseAddress,
			Buffer,
			BufferSize,
			NumberOfBytesRead);
		goto _CleanUp;
		//}
	}/*else if (IsFromGameProcess())
	 {
	 nStatus = ObReferenceObjectByHandle(ProcessHandle,
	 0,
	 *PsProcessType,
	 KernelMode,
	 (PVOID*)&pProcess,
	 NULL);
	 if (!NT_SUCCESS(nStatus))
	 {
	 goto _CleanUp;
	 }
	 ObDereferenceObject(pProcess);
	 if (pProcess == g_OwnInfo.pProtectedProcess)
	 {
	 nStatus = STATUS_ACCESS_DENIED;
	 goto _CleanUp;
	 }
	 }*/
	//二者都不是
	nStatus = ((NTREADVIRTUALMEMORY)g_ServiceFuncAddr.dwNtReadVirtualMemory)(ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesRead);
_CleanUp:
	InterlockedDecrement(&g_HookReferCnt[1]);
	return nStatus;
}

NTSTATUS
	__stdcall
	NewNtWriteVirtualMemory (
	__in HANDLE ProcessHandle,
	__in_opt PVOID BaseAddress,
	__in_bcount(BufferSize) CONST VOID *Buffer,
	__in SIZE_T BufferSize,
	__out_opt PSIZE_T NumberOfBytesWritten
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;

	InterlockedIncrement(&g_HookReferCnt[2]);

	if (PsGetCurrentProcess() == g_OwnInfo.pProtectedProcess)
	{
		nStatus = ((NTWRITEVIRTUALMEMORY)g_ServiceFuncAddr.dwReloadNtWriteVirtualMemory)(ProcessHandle,
			BaseAddress,
			Buffer,
			BufferSize,
			NumberOfBytesWritten);
		goto _CleanUp;
		//}
	}

	//二者都不是
	nStatus =((NTWRITEVIRTUALMEMORY)g_ServiceFuncAddr.dwNtWriteVirtualMemory)(ProcessHandle,
		BaseAddress,
		Buffer,
		BufferSize,
		NumberOfBytesWritten);
_CleanUp:
	InterlockedDecrement(&g_HookReferCnt[2]);
	return nStatus;
}
/**/
NTSTATUS
	__stdcall
	NewNtCreateThread(
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess,
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientId,
	__in PCONTEXT ThreadContext,
	__in PVOID InitialTeb,
	__in BOOL CreateSuspended
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	InterlockedIncrement(&g_HookReferCnt[3]);
	//avPrint("NewNtCreateThread called...");
	if (PsGetCurrentProcess() == g_OwnInfo.pProtectedProcess)
	{
		nStatus = ((NTCREATETHREAD)g_ServiceFuncAddr.dwReloadNtCreateThread)(ThreadHandle,
			DesiredAccess,
			ObjectAttributes,
			ProcessHandle,
			ClientId,
			ThreadContext,
			InitialTeb,
			CreateSuspended);
		goto _CleanUp;
	}
	nStatus = ((NTCREATETHREAD)g_ServiceFuncAddr.dwNtCreateThread)(ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		ClientId,
		ThreadContext,
		InitialTeb,
		CreateSuspended);
_CleanUp:
	InterlockedDecrement(&g_HookReferCnt[3]);
	return nStatus;
}

//NTSTATUS __stdcall
//	NewNtCreateProcess(
//	__out PHANDLE ProcessHandle,
//	__in ACCESS_MASK DesiredAccess,
//	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
//	__in HANDLE ParentProcess,
//	__in BOOLEAN InheritObjectTable,
//	__in_opt HANDLE SectionHandle,
//	__in_opt HANDLE DebugPort,
//	__in_opt HANDLE ExceptionPort
//	)
//{
//
//	if (PsGetCurrentProcess() == g_OwnInfo.pProtectedProcess)
//	{
//		return ((PFN_NTCREATEPROCESS)g_ServiceFuncAddr.dwReloadNtCreateProcess)(ProcessHandle,
//			DesiredAccess,
//			ObjectAttributes,
//			ParentProcess,
//			InheritObjectTable,
//			SectionHandle,
//			DebugPort,
//			ExceptionPort);
//
//	}
//	return ((PFN_NTCREATEPROCESS)g_ServiceFuncAddr.dwNtCreateProcess)(ProcessHandle,
//		DesiredAccess,
//		ObjectAttributes,
//		ParentProcess,
//		InheritObjectTable,
//		SectionHandle,
//		DebugPort,
//		ExceptionPort);
//}
//
//NTSTATUS __stdcall
//	NewNtCreateProcessEx(
//	__out PHANDLE ProcessHandle,
//	__in ACCESS_MASK DesiredAccess,
//	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
//	__in HANDLE ParentProcess,
//	__in ULONG Flags,
//	__in_opt HANDLE SectionHandle,
//	__in_opt HANDLE DebugPort,
//	__in_opt HANDLE ExceptionPort,
//	__in ULONG JobMemberLevel
//	)
//{
//	if (PsGetCurrentProcess() == g_OwnInfo.pProtectedProcess)
//	{
//		return ((PFN_NTCREATEPROCESSEX)g_pServiceFuncAddr->dwReloadNtCreateProcessEx)(ProcessHandle,
//			DesiredAccess,
//			ObjectAttributes,
//			ParentProcess,
//			Flags,
//			SectionHandle,
//			DebugPort,
//			ExceptionPort,
//			JobMemberLevel);
//
//	}
//	return ((PFN_NTCREATEPROCESSEX)g_pServiceFuncAddr->dwNtCreateProcessEx)(ProcessHandle,
//		DesiredAccess,
//		ObjectAttributes,
//		ParentProcess,
//		Flags,
//		SectionHandle,
//		DebugPort,
//		ExceptionPort,
//		JobMemberLevel);
//}
//
NTSTATUS __stdcall NewNtSuspendProcess(
	__in HANDLE ProcessHandle
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	InterlockedIncrement(&g_HookReferCnt[4]);
	if (IsFromGameProcess())
	{
		nStatus = ObReferenceObjectByHandle(ProcessHandle,
			0,
			*PsProcessType,
			KernelMode,
			(PVOID*)&pProcess,
			NULL);
		if (!NT_SUCCESS(nStatus))
		{
			goto _CleanUp;
		}
		ObDereferenceObject(pProcess);
		if (pProcess == g_OwnInfo.pProtectedProcess)
		{
			nStatus = STATUS_ACCESS_DENIED;
			goto _CleanUp;
		}
		
	}
	nStatus = ((NTSUSPENDPROCESS)g_ServiceFuncAddr.dwNtSuspendProcess)(ProcessHandle);
_CleanUp:

	InterlockedDecrement(&g_HookReferCnt[4]);
	return nStatus;
}
NTSTATUS __stdcall NewNtSuspendThread(
	__in HANDLE ThreadHandle,
	__out_opt PULONG PreviousSuspendCount
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	PEPROCESS pProcess = NULL;
	PETHREAD pThread = NULL;
	InterlockedIncrement(&g_HookReferCnt[5]);
	if (IsFromGameProcess())
	{
		nStatus = ObReferenceObjectByHandle(ThreadHandle,
			0,
			*PsThreadType,
			KernelMode,
			(PVOID*)&pThread,
			NULL);
		if (!NT_SUCCESS(nStatus))
		{
			goto _CleanUp;
		}
		ObDereferenceObject(pThread);
		//通过线程句柄获取进程
		pProcess = IoThreadToProcess(pThread);
		if (pProcess == g_OwnInfo.pProtectedProcess)
		{
			nStatus = STATUS_ACCESS_DENIED;
			goto _CleanUp;
		}
	}
	nStatus = ((NTSUSPENDTHREAD)g_ServiceFuncAddr.dwNtSuspendThread)(ThreadHandle,PreviousSuspendCount);
_CleanUp:

	InterlockedDecrement(&g_HookReferCnt[5]);
	return nStatus;
}

NTSTATUS __stdcall NewNtCreateFile (
	__out PHANDLE FileHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__out PIO_STATUS_BLOCK IoStatusBlock,
	__in_opt PLARGE_INTEGER AllocationSize,
	__in ULONG FileAttributes,
	__in ULONG ShareAccess,
	__in ULONG CreateDisposition,
	__in ULONG CreateOptions,
	__in_bcount_opt(EaLength) PVOID EaBuffer,
	__in ULONG EaLength
	)
{
	NTSTATUS nStatus = STATUS_SUCCESS;
	UNICODE_STRING uFakeObjectName = {0};
	InterlockedIncrement(&g_HookReferCnt[6]);


	if (IsFromGameProcess())
	{
		if (ObjectAttributes)
		{
			if (ValidateUnicodeString(ObjectAttributes->ObjectName))
			{
				//DbgPrint("filepath : %wZ\n",ObjectAttributes->ObjectName);
				if (wcsstr(ObjectAttributes->ObjectName->Buffer,wOwnDmDll) ||
					wcsstr(ObjectAttributes->ObjectName->Buffer,wOwnProcessName))
				{
					//构造一个新的objectname
					RtlInitUnicodeString(&uFakeObjectName,wszRegeditPath);
					ObjectAttributes->ObjectName = &uFakeObjectName;
				}
			}
		}
	}



	nStatus = ((PFN_NTCREATEFILE)g_ServiceFuncAddr.dwNtCreateFile)(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);

	InterlockedDecrement(&g_HookReferCnt[6]);
	return nStatus;
}

//
//NTSTATUS __stdcall
//	NewNtLoadDriver (
//	__in PUNICODE_STRING DriverServiceName
//	)
//{
//	DbgPrint("DriverServiceName : %wZ\n",DriverServiceName);
//	//这个函数全部走新内核
//	return ((PFN_NTLOADDRIVER)g_pServiceFuncAddr->dwReloadNtLoadDriver)(DriverServiceName);
//}
//
//NTSTATUS __stdcall
//	NewNtSetSystemInformation (
//	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
//	__in_bcount_opt(SystemInformationLength) PVOID SystemInformation,
//	__in ULONG SystemInformationLength
//	)
//{
//	return ((PFN_NTSETSYSTEMINFORMATION)g_pServiceFuncAddr->dwReloadNtSetSystemInformation)(SystemInformationClass,
//		SystemInformation,
//		SystemInformationLength);
//}



//过滤函数，很重要啦
ULONG __stdcall FilterKiFastCallEntryWinXP(ULONG Index,
	ULONG FunctionAddress,
	PVOID KiServiceTable)
{
	if (KiServiceTable == (PVOID)KeServiceDescriptorTable->ServiceTable)
	{
		if (122 == Index)
		{
			return (ULONG)NewNtOpenProcess;
		}
		else if (186 == Index)
		{
			return (ULONG)NewNtReadVirtualMemory;
		}
		else if (277 == Index)
		{
			return (ULONG)NewNtWriteVirtualMemory;
		} 
		else if (37 == Index)
		{
			return (ULONG)NewNtCreateFile;
		}
		//else if (47 == Index)
		//{
		//	return (ULONG)NewNtCreateProcess;
		//}
		//else if (48 == Index)
		//{
		//	return (ULONG)NewNtCreateProcessEx;
		//}
		else if (53 == Index)
		{
			return (ULONG)NewNtCreateThread;
		}
		//else if (68 == Index)
		//{
		//	return (ULONG)NewNtDuplicateObject;
		//}
		//else if (253 == Index)
		//{
		//	return (ULONG)NewNtSuspendProcess;
		//}
		//else if (254 == Index)
		//{
		//	return (ULONG)NewNtSuspendThread;
		//}
	}
	return FunctionAddress;
}
//
//__declspec(naked) VOID HookKiFastCallEntryZone()
//{
//	NOP_PROC;
//	__asm jmp [s_OriFastCall.lpRetAddr]
//}

__declspec(naked) VOID HookKiFastCallEntryZone()
{
	__asm
	{
		//PUSHAD的入栈顺序是:EAX、ECX、EDX、EBX、ESP、EBP、ESI、EDI
		mov edi,edi
			pushfd
			pushad

			push edi
			push ebx
			push eax
			call FilterKiFastCallEntryWinXP
			mov dword ptr [esp+10h],eax
			popad
			popfd
			sub esp,ecx
			shr ecx,2
			jmp [s_HookInfo.lpRetAddr]
	}
}
//nt!KiFastCallEntry+0xcc:
//8053e6ac ff0538f6dfff    inc     dword ptr ds:[0FFDFF638h]
//8053e6b2 8bf2            mov     esi,edx
//8053e6b4 8b5f0c          mov     ebx,dword ptr [edi+0Ch]
//8053e6b7 33c9            xor     ecx,ecx
//8053e6b9 8a0c18          mov     cl,byte ptr [eax+ebx]
//8053e6bc 8b3f            mov     edi,dword ptr [edi]
//8053e6be 8b1c87          mov     ebx,dword ptr [edi+eax*4]
//8053e6c1 e92a8fbf01      jmp     821375f0
VOID HookKiFastCallEntryMiddle()
{
	//如果有360的话也hook
	ULONG dwOriginKiFastCallEntry = 0;
	BYTE bySignCode[5]={0x8b,0x3f,0x8b,0x1c,0x87};
	BYTE byJmpCode[5] = {0xe9,0,0,0,0};
	ULONG dwHookAddr = 0;
	KIRQL kOldIrql;
	//ULONG dwReloadKiFastCallEntry = 0;
	dwOriginKiFastCallEntry = GetOriginKiFastCallEntryAddress();
	if (!dwOriginKiFastCallEntry)
	{
		return;
	}
	//dwReloadKiFastCallEntry = dwOriginKiFastCallEntry - (ULONG)g_NtosInfo.pOriginKernelBase +
	//			(ULONG)g_NtosInfo.pReloadKernelBase;
	dwHookAddr = SeachSignCode((BYTE*)dwOriginKiFastCallEntry,4096,bySignCode,5);
	if (!dwHookAddr)
	{
		return;
	}
	dwHookAddr +=5;
	if (*(BYTE*)dwHookAddr == 0xe9)
	{
		avPrint("The System has installed 360 safe...");
	}
	*(PULONG)(byJmpCode+1)=(ULONG)HookKiFastCallEntryZone-dwHookAddr-5;
	//s_HookInfo.dwPatchLength = 5;
	s_HookInfo.lpNewAddr = HookKiFastCallEntryZone;
	s_HookInfo.lpOriginAddr = (PVOID)dwHookAddr;
	s_HookInfo.lpRetAddr = (PVOID)(dwHookAddr+5);
	//
	kOldIrql = KeRaiseIrqlToDpcLevel();
	WProtectOff();
	RtlCopyMemory(s_byHookCode,(PBYTE)dwHookAddr,5);
	RtlCopyMemory((PUCHAR)dwHookAddr,byJmpCode,5);
	WProtectOn();
	KeLowerIrql(kOldIrql);
	s_bIsHookSuccessed = TRUE;
	avPrint("HookReloadKiFastCallEntryMiddle success...");
	//
	//s_OriFastCall.lpOriginAddr = (PVOID)dwOriginKiFastCallEntry;
	//s_OriFastCall.lpNewAddr = (PVOID)dwReloadKiFastCallEntry;
	//s_OriFastCall.lpHookZoneAddr = HookKiFastCallEntryZone;
	//if(HookFunctionByHeaderAddress(&s_OriFastCall))
	//{
	//	s_bIsHookSuccessed = TRUE;
	//	avPrint("HookOriginKiFastCallEntryHeader success...");
	//}
}
VOID UnhookKiFastCallEntryMiddle()
{
	KIRQL kOldIrql;
	if (s_bIsHookSuccessed)
	{
		kOldIrql = KeRaiseIrqlToDpcLevel();
		WProtectOff();
		//RtlCopyMemory(s_byHookCode,(PBYTE)dwHookAddr,5);
		RtlCopyMemory((PUCHAR)s_HookInfo.lpOriginAddr,s_byHookCode,5);
		WProtectOn();
		KeLowerIrql(kOldIrql);
		avPrint("UnhookKiFastCallEntryMiddle success...");
	}
}
//
VOID WaitReferCntSubToZero()
{
	ULONG dwCnt	= 0;
	while(1)
	{
		for (dwCnt = 0; dwCnt < MAX_REFER_CNT; dwCnt++)
		{
			if (g_HookReferCnt[dwCnt] == 0)
			{
				continue;
			}
			else
			{
				break;
			}
		}


		if (dwCnt == MAX_REFER_CNT)
		{
			break;
		}
	}
}