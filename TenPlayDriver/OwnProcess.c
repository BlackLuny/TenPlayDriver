#include "OwnProcess.h"
CHAR OwnProcessName[30] = "TianChen.exe";
CHAR OwnDmDll[30]="dm.dll";
WCHAR wOwnProcessName[30] = L"TianChen.exe";
WCHAR wOwnDmDll[30]= L"dm.dll";

static WCHAR s_wszSvchostPath[]= L"\\Windows\\System32\\svchost.exe";
static UNICODE_STRING s_uSvchostPath = {0};
static CHAR s_szsvchostName[]="svchost.exe";
//static CHAR OwnProcessName[30] = "taskmgr.exe";
static WCHAR OwnProcessFullPath[260]={0};
OWNPROCESS_INFO g_OwnInfo = {0};

// 指明遍历哪个句柄表,0表示全局句柄表
static CID_TABLE cid = {0};

NTSTATUS InitOwnProcess(PEPROCESS Eprocess)
{
	NTSTATUS nStatus					= STATUS_SUCCESS;
	//PEPROCESS pProtectedProcess			= NULL;
	/*strcpy_s(&g_ProtectedProcess.szOwnProcessName[0],strlen(OwnProcessName),OwnProcessName);*/
	UNICODE_STRING uNtPath				= {0};
	WCHAR		*pNtPathBuffer			= NULL;
	UNICODE_STRING uDeviceName			={0};
	WCHAR		*pDeviceName			= NULL;
	//nStatus = LookupProcessByName(OwnProcessName,&pProtectedProcess);
	//if (!NT_SUCCESS(nStatus))
	//{
	//	return nStatus;
	//}
	g_OwnInfo.pProtectedProcess = Eprocess;
	g_OwnInfo.dwPid = *(PULONG)((ULONG)Eprocess+0x84);
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

	nStatus = avQueryProcessFullPath(Eprocess,&uNtPath);

	if (!NT_SUCCESS(nStatus))
	{
		
		avPrint("avQueryProcessFullPath failed...");
		goto _ClearUp;
	}
	RtlCopyUnicodeString(&g_OwnInfo.uOwnProcessFullPath,&uNtPath);
	/*\Device\HarddiskVolume1\Documents and*/
	DbgPrint("OwnProcessFullPath : %wZ\n",&g_OwnInfo.uOwnProcessFullPath);
_ClearUp:
	if (pNtPathBuffer)
	{
		ExFreePool(pNtPathBuffer);
		pNtPathBuffer = NULL;
	}
	return nStatus;
}
//
//
BOOL ReplaceUnicodeString(PUNICODE_STRING pDestStr,PUNICODE_STRING pSrcString)
{
	KIRQL irql;
	if(pDestStr == NULL)return FALSE;

	//当目的buffer大小 < 要覆盖的buffer 长度的话，会有危险
	//if (pDestStr->MaximumLength < pSrcString->Length)
	//{
	//	CodeVprint("pDestStr->MaximumLength < uniSvchostString.Length\n");
	//	return FALSE;
	//}
	irql = KeRaiseIrqlToDpcLevel();
	WProtectOff();
	RtlCopyUnicodeString(pDestStr,pSrcString);
	WProtectOn();
	KeLowerIrql(irql);
	return TRUE;
}
//
BOOL RelaceString(PCHAR pDesStr,PCHAR pSrcString)
{
	KIRQL irql;
	if (pDesStr == NULL)return FALSE;
	//目的buffer是16个大小吧
	irql = KeRaiseIrqlToDpcLevel();
	WProtectOff();
	strcpy(pDesStr,pSrcString);
	WProtectOn();
	KeLowerIrql(irql);
	return TRUE;
}
//
VOID RecoverHideProcess()
{
	PUNICODE_STRING pPath = NULL;
	ULONG tmp = 0;
	if (g_OwnInfo.pProtectedProcess != NULL)
	{
		RelaceString((PCHAR)((ULONG)g_OwnInfo.pProtectedProcess+0x174),OwnProcessName);
		pPath = (PUNICODE_STRING)(*(PULONG)((ULONG)g_OwnInfo.pProtectedProcess + 0x1F4));

		ReplaceUnicodeString(pPath,&g_OwnInfo.uOwnProcessFullPath);

		tmp=*(PULONG)((ULONG)g_OwnInfo.pProtectedProcess+0x138);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)(tmp+0x14);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)tmp;
				if (MmIsAddressValidEx((PVOID)tmp))
				{
					tmp=*(PULONG)(tmp+0x024);
					if (MmIsAddressValidEx((PUNICODE_STRING)(tmp+0x030)))
					{
						ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&g_OwnInfo.uOwnProcessFullPath);
					}
				}
			}
		}
		//VAD
		//should use MmIsAddressValid to verify
		tmp=*(PULONG)((ULONG)g_OwnInfo.pProtectedProcess+0x11c);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)(tmp+0x10);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x018);
				if (MmIsAddressValidEx((PVOID)tmp))
				{
					tmp=*(PULONG)(tmp+0x024);
					if (MmIsAddressValidEx((PVOID)(tmp+0x030)))
					{
						ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&g_OwnInfo.uOwnProcessFullPath);
					}
				}
			}
		}
	}

}
//
VOID HideOwnProcess()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	KAPC_STATE ApcState;
	ULONG pPebAddress = 0;
	ULONG ProcessParameters=0,ldr =0,tmp = 0;
	PUNICODE_STRING pPath = NULL;

	//+0x1b0 Peb              : Ptr32 _PEB
	//pPebAddress = *(PULONG)((ULONG)ProtectProcess+0x1b0);
	//pKeStackAttachProcess(ProtectProcess,&ApcState);
	//__try
	//{
	//	ProcessParameters = *(PULONG)(pPebAddress + 0x010);
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x038));
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x040));
	//	ReplaceUnicodeString((PUNICODE_STRING)(ProcessParameters+0x070));
	//	//
	//	ldr = *(PULONG)(pPebAddress + 0x00c);
	//	//暂时不考虑这里
	//}
	//__except(1){}

	//pKeUnstackAttachProcess(&ApcState);
	//
	RelaceString((PCHAR)((ULONG)g_OwnInfo.pProtectedProcess+0x174),s_szsvchostName);
	pPath = (PUNICODE_STRING)(*(PULONG)((ULONG)g_OwnInfo.pProtectedProcess + 0x1F4));
	//先保存原来的path
	//RtlCopyMemory((BYTE*)s_wszOwnProcessPath,(BYTE*)pPath->Buffer,pPath->MaximumLength);
	//wcscpy_s(s_wszOwnProcessPath,pPath->MaximumLength,pPath->Buffer);
	//RtlInitUnicodeString(&s_uOwnProcessPath,s_wszOwnProcessPath);
	s_uSvchostPath.Length = (wcslen(s_wszSvchostPath) + 1) * sizeof(WCHAR);
	s_uSvchostPath.MaximumLength = s_uSvchostPath.Length;
	s_uSvchostPath.Buffer = s_wszSvchostPath;
	ReplaceUnicodeString(pPath,&s_uSvchostPath);
	//
	tmp=*(PULONG)((ULONG)g_OwnInfo.pProtectedProcess+0x138);
	if (MmIsAddressValidEx((PVOID)tmp))
	{
		tmp=*(PULONG)(tmp+0x14);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)tmp;
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x024);
				if (MmIsAddressValidEx((PUNICODE_STRING)(tmp+0x030)))
				{
					ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uSvchostPath);
				}
			}
		}
	}
	//VAD
	//should use MmIsAddressValid to verify
	tmp=*(PULONG)((ULONG)g_OwnInfo.pProtectedProcess+0x11c);
	if (MmIsAddressValidEx((PVOID)tmp))
	{
		tmp=*(PULONG)(tmp+0x10);
		if (MmIsAddressValidEx((PVOID)tmp))
		{
			tmp=*(PULONG)(tmp+0x018);
			if (MmIsAddressValidEx((PVOID)tmp))
			{
				tmp=*(PULONG)(tmp+0x024);
				if (MmIsAddressValidEx((PVOID)(tmp+0x030)))
				{
					ReplaceUnicodeString((PUNICODE_STRING)(tmp+0x030),&s_uSvchostPath);
				}
			}
		}
	}

}