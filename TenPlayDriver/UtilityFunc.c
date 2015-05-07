#include "UtilityFunc.h"


VOID WProtectOff()  
{
	__asm
	{
		cli
			mov eax,cr0
			and eax,not 10000h
			mov cr0,eax
	}
}
//内存恢复，不可写/////////////////////////////////////////////////////
VOID WProtectOn()  
{
	__asm
	{
		mov eax,cr0
			or eax,10000h
			mov cr0,eax
			sti
	}
}
/* 获取ntos中导出函数的地址 */
PVOID GetExortedFunctionAddress(PWCHAR FunctionName)
{
	UNICODE_STRING UniFunctionName = {0};
	RtlInitUnicodeString(&UniFunctionName,FunctionName);
	return MmGetSystemRoutineAddress(&UniFunctionName);
}
//////////////////////////////////////////////////////////////////////////
__inline ULONG CR4()
{
	// mov eax, cr4
	__asm _emit 0x0F __asm _emit 0x20 __asm _emit 0xE0
}
VALIDITY_CHECK_STATUS MmIsAddressValidExNotPae(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS  Return = VCS_INVALID;
	MMPTE* Pde;
	MMPTE* Pte;
	MMPTE pte;

	Pde = MiGetPdeAddress(Pointer);

	//KdPrint(("PDE is 0x%08x\n", Pde));
	if( Pde->u.Hard.Valid )
	{
		//KdPrint(("PDE entry is valid, PTE PFN=%08x\n", Pde->u.Hard.PageFrameNumber));

		Pte = MiGetPteAddress(Pointer);

		//KdPrint(("PTE is 0x%08x\n", Pte));
		if( Pte->u.Hard.Valid )
		{
			//KdPrint(("PTE entry is valid, PFN=%08x\n", Pte->u.Hard.PageFrameNumber));
			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			//KdPrint(("Got invalid PTE [%08x]: Proto=%d,Transition=%d,Protection=0x%x,PageFilePFN=0x%x\n",
			//	pte.u.Long,
			//	pte.u.Soft.Prototype,
			//	pte.u.Soft.Transition,
			//	pte.u.Soft.Protection,
			//	pte.u.Soft.PageFileHigh));

			if( pte.u.Long )
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					//KdPrint(("PTE entry is not valid, points to prototype PTE.\n"));

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page. Consider it invalid.
						//

						//KdPrint(("PTE entry is not valid, points to transition page.\n"));

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						//KdPrint(("PTE entry is not valid, points to demand-zero page.\n"));

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							//KdPrint(("PTE entry is not valid, VA is paged out (PageFile offset=%08x)\n",
							//	pte.u.Soft.PageFileHigh));

							Return = VCS_PAGEDOUT;
						}
						else
						{
							//KdPrint(("PTE entry is not valid, Refault\n"));
						}
					}
				}
			}
			else
			{
				//KdPrint(("PTE entry is completely invalid\n"));
			}
		}
	}
	else
	{
		//KdPrint(("PDE entry is not valid\n"));
	}

	return Return;
}
VALIDITY_CHECK_STATUS MmIsAddressValidExPae(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS Return = VCS_INVALID;
	MMPTE_PAE* Pde;
	MMPTE_PAE* Pte;
	MMPTE_PAE pte;

	Pde = MiGetPdeAddressPae(Pointer);

	//KdPrint(("PDE is at 0x%08x\n", Pde));
	if( Pde->u.Hard.Valid )
	{
		//KdPrint(("PDE entry is valid, PTE PFN=%08x\n", Pde->u.Hard.PageFrameNumber));

		if( Pde->u.Hard.LargePage != 0 )
		{
			//
			// This is a large 2M page
			//

			//KdPrint(("! PDE points to large 2M page\n"));

			Pte = Pde;
		}
		else
		{
			//
			// Small 4K page
			//

			// Get its PTE
			Pte  = MiGetPteAddressPae(Pointer);
		}

		//KdPrint(("PTE is at 0x%08x\n", Pte));
		if( Pte->u.Hard.Valid )
		{
			//KdPrint(("PTE entry is valid, PFN=%08x\n", Pte->u.Hard.PageFrameNumber));

			Return = VCS_VALID;
		}
		else
		{
			//
			// PTE is not valid
			//

			pte = *Pte;

			//KdPrint(("Got invalid PTE [%08x%08x]\n", pte.u.Long.HighPart, pte.u.Long.LowPart));

			if( pte.u.Long.LowPart == 0 )
			{
				//KdPrint(("PTE entry is completely invalid (page is not committed or is within VAD tree)\n"));
			}
			else
			{
				if( pte.u.Soft.Prototype == 1 )
				{
					// 					//KdPrint(("PTE entry is not valid, points to prototype PTE. Protection=%x[%s], ProtoAddress=%x\n",
					// 						(ULONG)pte.u.Proto.Protection,
					// 						MiPageProtectionString((UCHAR)pte.u.Proto.Protection),
					// 						(ULONG)pte.u.Proto.ProtoAddress));

					// more accurate check should be performed here for pointed prototype PTE!

					Return = VCS_PROTOTYPE;
				}
				else  // not a prototype PTE
				{
					if( pte.u.Soft.Transition != 0 )
					{
						//
						// This is a transition page.
						//

						// 						//KdPrint(("PTE entry is not valid, points to transition page. PFN=%x, Protection=%x[%s]\n",
						// 							(ULONG)pte.u.Trans.PageFrameNumber,
						// 							(ULONG)pte.u.Trans.Protection,
						// 							MiPageProtectionString((UCHAR)pte.u.Trans.Protection)));

						Return = VCS_TRANSITION;
					}
					else if (pte.u.Soft.PageFileHigh == 0)
					{
						//
						// Demand zero page
						//

						// 						//KdPrint(("PTE entry is not valid, points to demand-zero page. Protection=%x[%s]\n",
						// 							(ULONG)pte.u.Soft.Protection,
						// 							MiPageProtectionString((UCHAR)pte.u.Soft.Protection)));

						Return = VCS_DEMANDZERO;
					}
					else
					{
						//
						// Pagefile PTE
						//

						if( pte.u.Soft.Transition == 0 )
						{
							// 							//KdPrint(("PTE entry is not valid, VA is paged out. PageFile Offset=%08x, Protection=%x[%s]\n",
							// 								(ULONG)pte.u.Soft.PageFileHigh,
							// 								(ULONG)pte.u.Soft.Protection,
							// 								MiPageProtectionString((UCHAR)pte.u.Soft.Protection)));

							Return = VCS_PAGEDOUT;
						}
						else
						{
							//KdPrint(("PTE entry is not valid, Refault\n"));
						}
					}
				}
			}
		}
	}
	else
	{
		//KdPrint(("PDE entry is not valid\n"));
	}

	return Return;
}
VALIDITY_CHECK_STATUS MiIsAddressValidEx(
	IN PVOID Pointer
	)
{
	if( CR4() & PAE_ON ) {
		return MmIsAddressValidExPae(Pointer);
	}
	else {
		return MmIsAddressValidExNotPae(Pointer);
	}
}
BOOL MmIsAddressValidEx(
	IN PVOID Pointer
	)
{
	VALIDITY_CHECK_STATUS MmRet;
	ULONG ulTry;

	if (!ARGUMENT_PRESENT(Pointer) ||
		!Pointer){
		return FALSE;
	}
	/*
	//VCS_TRANSITION、VCS_PAGEDOUT内存居然是这样子~~擦~

	lkd> dd f8ad5ad8
	f8ad5ad8  ???????? ???????? ???????? ????????
	f8ad5ae8  ???????? ???????? ???????? ????????
	f8ad5af8  ???????? ???????? ???????? ????????
	f8ad5b08  ???????? ???????? ???????? ????????
	f8ad5b18  ???????? ???????? ???????? ????????
	f8ad5b28  ???????? ???????? ???????? ????????
	f8ad5b38  ???????? ???????? ???????? ????????
	f8ad5b48  ???????? ???????? ???????? ????????
	*/
	MmRet = MiIsAddressValidEx(Pointer);
	if (MmRet != VCS_VALID){
		return FALSE;
	}
	return TRUE;
}
/************************************************************************/
//对源地址的数据进行安全拷贝，再对拷贝后的数据进行操作
//
/************************************************************************/
NTSTATUS SafeCopyMemory(PVOID SrcAddr, PVOID DstAddr, ULONG Size)
{
	PMDL  pSrcMdl, pDstMdl;
	PUCHAR pSrcAddress, pDstAddress;
	NTSTATUS st = STATUS_UNSUCCESSFUL;
	ULONG r;
	BOOL bInit = FALSE;

	pSrcMdl = IoAllocateMdl(SrcAddr, Size, FALSE, FALSE, NULL);
	if (MmIsAddressValidEx(pSrcMdl))
	{
		MmBuildMdlForNonPagedPool(pSrcMdl);
		pSrcAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pSrcMdl, NormalPagePriority);
		if (MmIsAddressValidEx(pSrcAddress))
		{
			pDstMdl = IoAllocateMdl(DstAddr, Size, FALSE, FALSE, NULL);
			if (MmIsAddressValidEx(pDstMdl))
			{
				__try
				{
					MmProbeAndLockPages(pDstMdl, KernelMode, IoWriteAccess);
					pDstAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(pDstMdl, NormalPagePriority);
					if (MmIsAddressValidEx(pDstAddress))
					{
						RtlZeroMemory(pDstAddress,Size);
						RtlCopyMemory(pDstAddress, pSrcAddress, Size);
						st = STATUS_SUCCESS;
					}
					MmUnlockPages(pDstMdl);
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{                 
					if (pDstMdl) MmUnlockPages(pDstMdl);

					if (pDstMdl) IoFreeMdl(pDstMdl);

					if (pSrcMdl) IoFreeMdl(pSrcMdl);

					return GetExceptionCode();
				}
				IoFreeMdl(pDstMdl);
			}
		}            
		IoFreeMdl(pSrcMdl);
	}
	return st;
}
//
/**/
ULONG GetOriginKiFastCallEntryAddress()
{
	ULONG uKiFastCallEntry=0;
	__asm
	{
		pushad
			mov ecx,0x176
			rdmsr
			mov uKiFastCallEntry,eax
			popad
	}
	return uKiFastCallEntry;
}
//
BOOL IsFromGameProcess()
{
	BOOL bRet = FALSE;
	ULONG i=0;
	PCHAR ProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
	if (ProcessName)
	{
		for (i=0;i<GAME_PROCESS_COUNT;i++)
		{
			if (_stricmp(ProcessName,GameProcessName[i])==0)
			{
				bRet = TRUE;
				break;
			}
		}
	}
	return bRet;
}
//
NTSTATUS LookupProcessByName(
	IN PCHAR pcProcessName,
	OUT PEPROCESS *pEprocess
	)
{ 
	NTSTATUS	status;
	ULONG		uCount = 0;
	ULONG		uLength = 0;
	PLIST_ENTRY	pListActiveProcess = NULL;
	PEPROCESS	pCurrentEprocess = NULL;
	ULONG ulNextProcess = 0;
	ULONG g_Offset_Eprocess_Flink = 0;
	char lpszProName[100] = {0};
	char *lpszAttackProName = NULL;


	if (!ARGUMENT_PRESENT(pcProcessName) || !ARGUMENT_PRESENT(pEprocess))
	{
		return STATUS_INVALID_PARAMETER;
	}
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	uLength = strlen(pcProcessName);

	//WinVer = GetWindowsVersion();
	switch(WinVersion)
	{
	case WINDOWS_VERSION_XP:
		g_Offset_Eprocess_Flink = 0x88;
		break;
	case WINDOWS_VERSION_7_7600_UP:
	case WINDOWS_VERSION_7_7000:
		g_Offset_Eprocess_Flink = 0xb8;
		break;
	case WINDOWS_VERSION_VISTA_2008:
		g_Offset_Eprocess_Flink = 0x0a0;
		break;
	case WINDOWS_VERSION_2K3_SP1_SP2:
		g_Offset_Eprocess_Flink = 0x98;
		break;
	case WINDOWS_VERSION_2K3:
		g_Offset_Eprocess_Flink = 0x088;
		break;
	}
	if (!g_Offset_Eprocess_Flink){
		return STATUS_UNSUCCESSFUL;
	}

	pCurrentEprocess = PsGetCurrentProcess();
	ulNextProcess = (ULONG)pCurrentEprocess;
	__try
	{
		memset(lpszProName,0,sizeof(lpszProName));
		if (uLength > 15)
		{
			strncat(lpszProName,pcProcessName,15);
		}
		while(1)
		{
			lpszAttackProName = NULL;
			lpszAttackProName = (char *)PsGetProcessImageFileName(pCurrentEprocess);

			if (uLength > 15)
			{
				if (lpszAttackProName &&
					strlen(lpszAttackProName) == uLength)
				{
					if(_strnicmp(lpszProName,lpszAttackProName, uLength) == 0)
					{
						*pEprocess = pCurrentEprocess;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
			else
			{
				if (lpszAttackProName &&
					(strlen(lpszAttackProName) == uLength))
				{
					if(_strnicmp(pcProcessName,lpszAttackProName, uLength) == 0)
					{
						*pEprocess = pCurrentEprocess;
						status = STATUS_SUCCESS;
						break;
					}
				}
			}
			if ((uCount >= 1) && ((PEPROCESS)ulNextProcess == pCurrentEprocess))
			{
				*pEprocess = 0x00000000;
				status = STATUS_NOT_FOUND;
				break;
			}
			pListActiveProcess = (LIST_ENTRY *)((ULONG)pCurrentEprocess + g_Offset_Eprocess_Flink);
			(ULONG)pCurrentEprocess = (ULONG)pListActiveProcess->Flink;
			(ULONG)pCurrentEprocess = (ULONG)pCurrentEprocess - g_Offset_Eprocess_Flink;
			uCount++;
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("LookupProcessByName:%08x",GetExceptionCode());
		status = STATUS_NOT_FOUND;
	}
	return status;
}
//
NTSTATUS avQueryProcessFullPath(IN PEPROCESS pProcess,OUT PUNICODE_STRING pUniProcessPath)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	HANDLE hProcess = NULL;
	PFN_ZWQUERYINFORMATIONPROCESS pfnZwQueryInformationProcess;
	ULONG dwReturnLength = 0;
	ULONG dwBufferLength = 0;
	PVOID Buffer = NULL;
	PUNICODE_STRING pUniImageName = NULL;
	nStatus = ObOpenObjectByPointer(pProcess,
		OBJ_KERNEL_HANDLE,
		NULL,
		GENERIC_READ,
		*PsProcessType,
		KernelMode,
		&hProcess);
	if (!NT_SUCCESS(nStatus))
	{
		return nStatus;
	}
	pfnZwQueryInformationProcess = (PFN_ZWQUERYINFORMATIONPROCESS)GetExortedFunctionAddress(L"ZwQueryInformationProcess");
	if (!pfnZwQueryInformationProcess)
	{
		ZwClose(hProcess);
		return STATUS_UNSUCCESSFUL;
	}
	nStatus = pfnZwQueryInformationProcess( hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0, // buffer size
		&dwReturnLength);

	if (STATUS_INFO_LENGTH_MISMATCH != nStatus)
	{
		ZwClose(hProcess);
		return nStatus;

	} 
	//
	// Is the passed-in buffer going to be big enough for us? 
	// This function returns a single contguous buffer model...
	//
	dwBufferLength = dwReturnLength - sizeof(UNICODE_STRING);

	if (pUniProcessPath->MaximumLength < dwBufferLength) 
	{

		//pUniProcessPath->Length = (USHORT) dwBufferLength;

		ZwClose(hProcess);
		return STATUS_BUFFER_OVERFLOW;

	} 
	//
	// If we get here, the buffer IS going to be big enough for us, so
	// let's allocate some storage.
	//
	Buffer = ExAllocatePoolWithTag(PagedPool, dwReturnLength, 'ipgD');

	if (NULL == Buffer) 
	{

		ZwClose(hProcess);
		return STATUS_INSUFFICIENT_RESOURCES;

	}
	RtlZeroMemory(Buffer,dwReturnLength);
	//
	// Now lets go get the data
	//
	nStatus = pfnZwQueryInformationProcess( hProcess,
		ProcessImageFileName,
		Buffer,
		dwReturnLength,
		&dwReturnLength);

	if (!NT_SUCCESS(nStatus)) 
	{
		ZwClose(hProcess);
		ExFreePool(Buffer);
		Buffer = NULL;
		return nStatus;
	} 
	//
	// Ah, we got what we needed
	//
	pUniImageName = (PUNICODE_STRING) Buffer;

	RtlCopyUnicodeString(pUniProcessPath, pUniImageName);
	//over
	ZwClose(hProcess);
	ExFreePool(Buffer);
	Buffer = NULL;
	return nStatus;
}
//

NTSTATUS avQueryDeviceNameFromSymLink(IN PUNICODE_STRING pSymLink,
	OUT PUNICODE_STRING pDeviceName)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	HANDLE hSymLink = NULL;
	OBJECT_ATTRIBUTES			oa = {0};
	ULONG dwReturnLength	= 0;
	InitializeObjectAttributes(&oa,
		pSymLink,
		OBJ_CASE_INSENSITIVE,
		0,
		0);
	nStatus = ZwOpenSymbolicLinkObject(&hSymLink,
		GENERIC_READ,
		&oa);
	if (!NT_SUCCESS(nStatus))
	{
		return nStatus;
	}
	//获取句柄
	nStatus = ZwQuerySymbolicLinkObject(hSymLink,
		pDeviceName,
		&dwReturnLength);
	if (!NT_SUCCESS(nStatus))
	{
		ZwClose(hSymLink);
		hSymLink = NULL;
		return nStatus;
	}
	return nStatus;
}

NTSTATUS
	avRtlVolumeDeviceToDosName(
	IN PUNICODE_STRING DeviceName,
	OUT PUNICODE_STRING DosName
	)
{
	NTSTATUS					nStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING				uSymLinkName = {0};
	WCHAR						wszSymLinkNameBuffer[260]={0};
	WCHAR						c;
	WCHAR						wszSym[3] = {0};
	UNICODE_STRING				uTargetDeviceName = {0};
	HANDLE						hSymLink = NULL;
	OBJECT_ATTRIBUTES			oa = {0};
	WCHAR						*pTargetDeviceNameBuffer = NULL;
	ULONG						dwReturnLength = 0;
	pTargetDeviceNameBuffer = (WCHAR*)ExAllocatePoolWithTag(PagedPool,sizeof(wszSymLinkNameBuffer),'link');
	if (!pTargetDeviceNameBuffer)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlInitEmptyUnicodeString(&uTargetDeviceName,pTargetDeviceNameBuffer,sizeof(wszSymLinkNameBuffer));
	//ULONG i = 0;
	for (c = L'A'; c<= L'Z';c++ )
	{
		RtlInitEmptyUnicodeString(&uSymLinkName,wszSymLinkNameBuffer,sizeof(wszSymLinkNameBuffer));
		RtlAppendUnicodeToString(&uSymLinkName,L"\\??\\");
		wszSym[0]=c;
		wszSym[1]=L':';
		wszSym[2]=0;
		RtlAppendUnicodeToString(&uSymLinkName,wszSym);
		//DbgPrint("uSymLinkName : %wZ\n",&uSymLinkName);
		RtlZeroMemory(pTargetDeviceNameBuffer,sizeof(wszSymLinkNameBuffer));
		nStatus = avQueryDeviceNameFromSymLink(&uSymLinkName,&uTargetDeviceName);

		if (!NT_SUCCESS(nStatus))
		{
			continue;
		}
		if (RtlEqualUnicodeString(&uTargetDeviceName,DeviceName,TRUE))
		{
			break;
		}
	}
	if (NT_SUCCESS(nStatus))
	{
		if (c <= 'Z')//说明匹配到了一个符号链接
		{
			//RtlZeroMemory(wszSymLinkNameBuffer,sizeof(wszSymLinkNameBuffer));
			//wszSymLinkNameBuffer[0]=c;
			//wszSymLinkNameBuffer[1]=L':';
			//wszSymLinkNameBuffer[2]=0;
			//uSymLinkName.Length = sizeof(WCHAR)*2;
			//uSymLinkName.MaximumLength = sizeof(WCHAR)*3;
			//
			if (DosName->MaximumLength >= uSymLinkName.MaximumLength)
			{
				RtlCopyUnicodeString(DosName,&uSymLinkName);
			}
			else
			{
				//否则返回失败
				nStatus = STATUS_UNSUCCESSFUL;
			}
		}
	}
	return nStatus;
}
//
VOID avGetDeviceNameFromNtPath(PUNICODE_STRING pUniNtPath,OUT PUNICODE_STRING pUniDeviceName)
{
	WCHAR *pFirst,*pNext;
	USHORT wNumber = 0;//找到第三个
	WCHAR wszDeviceName[260]={0};
	pFirst = pNext = pUniNtPath->Buffer;
	while(*pNext)
	{
		if (*pNext == L'\\')
		{
			wNumber++;
			if (wNumber == 3)
			{
				break;
			}
		}
		pNext++;
	}
	RtlCopyMemory(wszDeviceName,pFirst,sizeof(WCHAR)*(pNext - pFirst));
	*(wszDeviceName+(pNext - pFirst)) = 0;
	RtlAppendUnicodeToString(pUniDeviceName,wszDeviceName);
	//pUniDeviceName->Length = wcslen(wszDeviceName)*sizeof(WCHAR);
}
//
VOID avGetDosDirFromDosFullPath(PUNICODE_STRING pDosFullPath)
{
	WCHAR *pFront;
	pFront = pDosFullPath->Buffer+ pDosFullPath->Length - 1;
	while(*pFront != L'\\')
	{
		*pFront-- = 0;
	}
	*pFront=0;
	pDosFullPath->Length = (pFront - pDosFullPath->Buffer)*sizeof(WCHAR);
}
//
/*睡眠指定秒的时间*/
VOID Sleep(LONG MSeconds)
{
	LARGE_INTEGER interval = {0};
	interval.QuadPart = - 10 * 1000 * MSeconds;
	KeDelayExecutionThread(KernelMode,FALSE,&interval);
}
//
BOOL ValidateUnicodeString(PUNICODE_STRING usStr)
{
	ULONG i = 0;

	__try
	{
		if (!MmIsAddressValid(usStr))
		{
			return FALSE;
		}
		if (usStr->Buffer == NULL || usStr->Length == 0)
		{
			return FALSE;
		}
		for (i = 0; i < usStr->Length; i++)
		{
			if (!MmIsAddressValid((PUCHAR)usStr->Buffer + i))
			{
				return FALSE;
			}
		}

	}__except(EXCEPTION_EXECUTE_HANDLER){

	}
	return TRUE;
}
//这里得到句柄表的句柄
NTSTATUS GetPspCidTable(PHANDLE_TABLE *pPspHandleAddr)
{
    /*
     kd> dd PspCidTable
     805649c0  e1000c88 00000002 00000000 00000000
    *///得到本机的PspTable地址为 805649c0

    /*另外，通过搜索PsLookupProcessByProcessId也可以
    u PsLookupProcessByProcessId

    805d40de 8bff            mov     edi,edi
    805d40e0 55              push    ebp
    805d40e1 8bec            mov     ebp,esp
    805d40e3 53              push    ebx
    805d40e4 56              push    esi
    805d40e5 64a124010000    mov     eax,dword ptr fs:[00000124h]
    805d40eb ff7508          push    dword ptr [ebp+8]
    805d40ee 8bf0            mov     esi,eax
    805d40f0 ff8ed4000000    dec     dword ptr [esi+0D4h]
    805d40f6 ff35c0495680    push    dword ptr [nt!PspCidTable (805649c0)]
    805d40fc e859ad0300      call    nt!ExMapHandleToPointer (8060ee5a)
    805d4101 8bd8            mov     ebx,eax
    805d4103 85db            test    ebx,ebx
    */
	BOOL bIsFind = FALSE;
    NTSTATUS Status = STATUS_SUCCESS;
    BYTE* pPsLookupProcessByProcessId = NULL;
    int i = 0;
    BYTE Findcode[] = { 0xff, 0x8e, 0xff, 0x35}; // WIN XP SP3
    ULONG Addr_PspCidTable = 0;

    //DbgPrint("进入函数\n");
    //uStartAddress=PsLookupProcessByProcessId;
    //DbgPrint("uStartAddress%x\n",uStartAddress);

    pPsLookupProcessByProcessId = ( BYTE * ) GetExortedFunctionAddress( L"PsLookupProcessByProcessId" );
	if (pPsLookupProcessByProcessId == NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
    for( i = 0; i < 100; i ++ )
    {
        if( pPsLookupProcessByProcessId[i] == Findcode[0] &&
                pPsLookupProcessByProcessId[i + 1] == Findcode[1] &&
                pPsLookupProcessByProcessId[i + 6] == Findcode[2] &&
                pPsLookupProcessByProcessId[i + 7] == Findcode[3]
          )
        {
			bIsFind = TRUE;
            Addr_PspCidTable = * ( ULONG* )( &pPsLookupProcessByProcessId[i + 8] );
            break;
        }
    }
	if (bIsFind)
	{
		    *pPspHandleAddr = ( PHANDLE_TABLE )Addr_PspCidTable;
			return STATUS_SUCCESS;
	}

    //CodeVprint( "PspCidTable地址:%x\n", * ( PULONG ) pPspHandleAddr );
    return STATUS_UNSUCCESSFUL;
}
