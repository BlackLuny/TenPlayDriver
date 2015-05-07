#include "NotifyRoutine.h"

extern KERNEL_MODULE_INFO g_NtosInfo;
extern SERVICE_FUNCTION_ADDR  g_ServiceFuncAddr;
extern PDRIVER_OBJECT g_MyDriverObject;
//
static INLINE_HOOK_INFO s_LoadImageInfo = {0};
//
static BOOL s_bIsLoadImageHooked = FALSE;
//
ULONG g_dwCreateProcessNotifyAddr;
ULONG g_dwCreateThreadNotifyAddr;
ULONG g_dwSetLoadImageNotifyAddr;
PVOID TpModuleBase = NULL;
//处理模块加载回调函数
//NtSetInformation-->>MmLoadSystemImage-->>PsCallImageNotifyRoutines
//
//nt!NtSetSystemInformation+0x35c:
//80607c62 8b03            mov     eax,dword ptr [ebx]
//80607c64 8945d8          mov     dword ptr [ebp-28h],eax
//80607c67 8b4304          mov     eax,dword ptr [ebx+4]
//80607c6a 8945dc          mov     dword ptr [ebp-24h],eax
//80607c6d 8d45ac          lea     eax,[ebp-54h]
//80607c70 50              push    eax
//80607c71 8d45b4          lea     eax,[ebp-4Ch]
//80607c74 50              push    eax
//80607c75 6a01            push    1
//80607c77 57              push    edi
//80607c78 57              push    edi
//80607c79 8d45d8          lea     eax,[ebp-28h]
//80607c7c 50              push    eax
//80607c7d e862ccf9ff      call    nt!MmLoadSystemImage (805a48e4)
//80607c82 8945e4          mov     dword ptr [ebp-1Ch],eax
//80607c85 3bc7            cmp     eax,edi
//80607c87 0f8cb0040000    jl      nt!NtSetSystemInformation+0x837 (8060813d)
ULONG avGetMmLoadSystemImageAddr(ULONG dwNtSetSystemInformationAddr)
{
	BYTE *p1,*p2;
	//BOOL bIsFind = FALSE;
	ULONG dwAddr = 0;
	p1 = p2 =(BYTE*)(dwNtSetSystemInformationAddr+0x35c);
	if (!MmIsAddressValidEx(p1))
	{
		return 0;
	}
	for (;p1 < p2+100;p1++)
	{
		if (*(p1) == 0xe8 &&
			*(p1 - 1) == 0x50 &&
			*(p1 - 4) == 0x8d &&
			*(p1 - 3) == 0x45 &&
			*(p1 - 2) == 0xd8 &&
			*(p1 + 8) == 0x3b )
		{
			dwAddr = (ULONG)p1 + *(PULONG)(p1+1) +5;
			/*bIsFind = TRUE;*/
			break;
		}
	}
	return dwAddr;
}
//
//nt!MmLoadSystemImage+0x9ae:
//805a5292 c785d8feffff03010000 mov dword ptr [ebp-128h],103h
//805a529c 8b4320          mov     eax,dword ptr [ebx+20h]
//805a529f 8985e4feffff    mov     dword ptr [ebp-11Ch],eax
//805a52a5 8b07            mov     eax,dword ptr [edi]
//805a52a7 8985dcfeffff    mov     dword ptr [ebp-124h],eax
//805a52ad 89b5e0feffff    mov     dword ptr [ebp-120h],esi
//805a52b3 89b5e8feffff    mov     dword ptr [ebp-118h],esi
//805a52b9 8d85d8feffff    lea     eax,[ebp-128h]
//805a52bf 50              push    eax
//805a52c0 56              push    esi
//805a52c1 ff7508          push    dword ptr [ebp+8]
//805a52c4 e841210200      call    nt!PsCallImageNotifyRoutines (805c740a)
ULONG avGetPsCallImageNotifyRoutinesAddr(ULONG dwNtSetSystemInformationAddr)
{
	ULONG dwAddr = 0;
	BYTE *p1,*p2;
	ULONG dwMmLoadSystemImage = avGetMmLoadSystemImageAddr(dwNtSetSystemInformationAddr);
	if (!dwMmLoadSystemImage)
	{
		return 0;
	}
	p1 = p2 = (BYTE *)(dwMmLoadSystemImage +0x9ae);
	if (!MmIsAddressValidEx(p1))
	{
		return 0;
	}
	for (;p1 < p2 + 100;p1++)
	{
		if (*(p1) == 0xe8 &&
			*(p1 - 3) == 0xff &&
			*(p1 - 2) == 0x75)
		{
			dwAddr = (ULONG)p1 + *(PULONG)(p1+1) +5;
			/*bIsFind = TRUE;*/
			break;
		}
	}
	return dwAddr;
}
//
VOID
	NewPsCallImageNotifyRoutines(
	IN PUNICODE_STRING FullImageName,
	IN HANDLE ProcessId,                // pid into which image is being mapped
	IN PIMAGE_INFO ImageInfo
	)
{
	//屏蔽掉所有回调？
	return;
}
__declspec(naked)VOID PsCallImageNotifyRoutinesZone()
{
	NOP_PROC
	__asm jmp [s_LoadImageInfo.lpRetAddr];
}
//
VOID HookPsCallImageNotifyRoutines()
{
	ULONG dwPsCallImageNotifyRoutines		= 0;
/*	ULONG dwReloadPsCallImageNotifyRoutines	= 0;*/
	dwPsCallImageNotifyRoutines = avGetPsCallImageNotifyRoutinesAddr(g_ServiceFuncAddr.dwNtSetSystemInformation);
	if (!dwPsCallImageNotifyRoutines)
	{
		return;
	}
/*
	dwReloadPsCallImageNotifyRoutines = dwPsCallImageNotifyRoutines - 
		(ULONG)g_NtosInfo.pOriginKernelBase + (ULONG)g_NtosInfo.pReloadKernelBase;*/
	if(!MmIsAddressValidEx((PVOID)dwPsCallImageNotifyRoutines))
	{
		return;
	}
	s_LoadImageInfo.lpNewAddr = NewPsCallImageNotifyRoutines;
	s_LoadImageInfo.lpOriginAddr = (PVOID)dwPsCallImageNotifyRoutines;
	s_LoadImageInfo.lpHookZoneAddr = PsCallImageNotifyRoutinesZone;

	if (HookFunctionByHeaderAddress(&s_LoadImageInfo))
	{
		s_bIsLoadImageHooked = TRUE;
		avPrint("HookPsCallImageNotifyRoutines success...");
	}


}
//
VOID UnhookPsCallImageNotifyRoutines()
{
	if (s_bIsLoadImageHooked)
	{
		UnHookFunctionByHeaderAddress(&s_LoadImageInfo);
		avPrint("UnhookPsCallImageNotifyRoutines success...");
	}
}
//

//nt!NtCreateThread+0xd7:
//805c8471 834dfcff        or      dword ptr [ebp-4],0FFFFFFFFh
//805c8475 52              push    edx
//805c8476 52              push    edx
//805c8477 ff7524          push    dword ptr [ebp+24h]
//805c847a 8d45c8          lea     eax,[ebp-38h]
//805c847d 50              push    eax
//805c847e ff751c          push    dword ptr [ebp+1Ch]
//805c8481 ff7518          push    dword ptr [ebp+18h]
//805c8484 52              push    edx
//805c8485 ff7514          push    dword ptr [ebp+14h]
//805c8488 ff7510          push    dword ptr [ebp+10h]
//805c848b ff750c          push    dword ptr [ebp+0Ch]
//805c848e ff7508          push    dword ptr [ebp+8]
//805c8491 e8c4efffff      call    nt!PspCreateThread (805c745a)
//805c8496 eb1a            jmp     nt!NtCreateThread+0x118 (805c84b2)
ULONG avGetPspCreateThreadAddr()
{
	ULONG dwAddr = 0;
	BYTE *p1,*p2;
	ULONG dwNtCreateThread = g_ServiceFuncAddr.dwNtCreateThread;
	p1 = p2 = (BYTE *)(dwNtCreateThread +0xd7);
	if (!MmIsAddressValidEx(p1))
	{
		return 0;
	}
	for (;p1 < p2 + 100;p1++)
	{
		if (*(p1) == 0xe8 &&
			*(p1 - 3) == 0xff &&
			*(p1 - 2) == 0x75 &&
			*(p1 - 1) == 0x08)
		{
			dwAddr = (ULONG)p1 + *(PULONG)(p1+1) +5;
			/*bIsFind = TRUE;*/
			break;
		}
	}
	return dwAddr;
}
//
//创建线程回调
//nt!PspCreateThread+0x3a0:
//805c77fa b201            mov     dl,1
//805c77fc 8bcb            mov     ecx,ebx
//805c77fe e863210300      call    nt!WmiTraceProcess (805f9966)
//805c7803 393d00b45580    cmp     dword ptr [nt!PspCreateProcessNotifyRoutineCount (8055b400)],edi
//805c7809 7444            je      nt!PspCreateThread+0x3f5 (805c784f)
VOID PatchReloadPspCreateThread()
{
	//cmp edi,0
	BYTE byPatchCode[6]={0x83,0xff,0x0,0x90,0x90,0x90};
	ULONG dwReloadPspCreateThread;
	BOOL bIsFind = FALSE;
	BYTE *p1,*p2;
	ULONG dwPspCreateThread = avGetPspCreateThreadAddr();

	if (!dwPspCreateThread)
	{
		return;
	}
	dwReloadPspCreateThread = dwPspCreateThread - 
		(ULONG)g_NtosInfo.pOriginKernelBase + (ULONG)g_NtosInfo.pReloadKernelBase;

	if (!MmIsAddressValidEx((PVOID)dwReloadPspCreateThread))
	{
		return;
	}
	//patch掉
	//805c7803 393d00b45580    cmp     dword ptr [nt!PspCreateProcessNotifyRoutineCount (8055b400)],edi
	p1 = p2 = (BYTE *)(dwReloadPspCreateThread + 0x3a0);
	for(;p1 < p2+30;p1++)
	{
		if (*(p1-5) == 0xe8)
		{
			bIsFind = TRUE;
			break;
		}
	}
	//patch我们自己的内核
	if (bIsFind)
	{
		RtlCopyMemory(p1,byPatchCode,6);
		avPrint("PatchReloadPspCreateThread one success...");
	}
	bIsFind = FALSE;
//nt!PspCreateThread+0x47e:
//805c78d8 6a01            push    1
//805c78da ff7524          push    dword ptr [ebp+24h]
//805c78dd 56              push    esi
//805c78de e82f220300      call    nt!WmiTraceThread (805f9b12)
//805c78e3 33ff            xor     edi,edi
//805c78e5 393dc0b35580    cmp     dword ptr [nt!PspCreateThreadNotifyRoutineCount (8055b3c0)],edi
//805c78eb 744d            je      nt!PspCreateThread+0x4e0 (805c793a)
	p1 = p2 = (BYTE *)(dwReloadPspCreateThread + 0x47e);
	for(;p1 < p2+30;p1++)
	{
		if (*(p1-1) == 0xff &&
			*(p1-2) == 0x33)
		{
			bIsFind = TRUE;
			break;
		}
	}
	//patch我们自己的内核
	if (bIsFind)
	{
		RtlCopyMemory(p1,byPatchCode,6);
		avPrint("PatchReloadPspCreateThread two success...");
	}
}

//////////////////////////////////////////////////////////////////////////
ULONG GetCreateProcessNotifyAddr()
{
	//805d0cb3 7464            je      nt!PsSetCreateProcessNotifyRoutine+0x73 (805d0d19)
	//nt!PsSetCreateProcessNotifyRoutine+0xf:
	//805d0cb5 bf404a5680      mov     edi,offset nt!PspCreateProcessNotifyRoutine (80564a40)
	//
	//nt!PsSetCreateProcessNotifyRoutine+0x14:
	//805d0cba 57              push    edi
	//805d0cbb e852d70300      call    nt!ExReferenceCallBackBlock (8060e412)
	ULONG ulPsSetCreateProcessNotifyRoutine;
	PUCHAR p;
	ULONG ulSize;
	ULONG i;
	ULONG ulAddress;
	BOOL bFind = FALSE;
	ulPsSetCreateProcessNotifyRoutine = 
		(ULONG)GetExortedFunctionAddress(L"PsSetCreateProcessNotifyRoutine");
	if (ulPsSetCreateProcessNotifyRoutine == 0)
	{
		return 0;
	}
	p = (PUCHAR)ulPsSetCreateProcessNotifyRoutine;
	ulSize = 0x1000;
	for (i=0;i<ulSize;i++,p++)
	{
		if (*(p-3)==0x74 &&
			*(p+5) ==0xe8)
		{
			if (MmIsAddressValidEx(p))
			{
				bFind = TRUE;
				ulAddress = *(PULONG)p;
			}
			break;
		}
	}
	if (!bFind)
	{
		return 0;
	}
	return ulAddress;
}
//
ULONG GetCreateThreadNotifyAddr()
{
	//nt!PsSetCreateThreadNotifyRoutine+0x18:
	//805d0d8e b89a0000c0      mov     eax,0C000009Ah
	//805d0d93 eb2a            jmp     nt!PsSetCreateThreadNotifyRoutine+0x49 (805d0dbf)
	//nt!PsSetCreateThreadNotifyRoutine+0x1f:
	//805d0d95 56              push    esi
	//805d0d96 be004a5680      mov     esi,offset nt!PspCreateThreadNotifyRoutine (80564a00)
	//nt!PsSetCreateThreadNotifyRoutine+0x25:
	//805d0d9b 6a00            push    0
	//805d0d9d 53              push    ebx
	//805d0d9e 56              push    esi
	//805d0d9f e8a2d50300      call    nt!ExCompareExchangeCallBack (8060e346)
	ULONG ulPsSetCreateThreadNotifyRoutine;
	PUCHAR p;
	ULONG ulSize;
	ULONG i;
	ULONG ulAddress;
	BOOL bFind = FALSE;
	ulPsSetCreateThreadNotifyRoutine = 
		(ULONG)GetExortedFunctionAddress(L"PsSetCreateThreadNotifyRoutine");
	if (ulPsSetCreateThreadNotifyRoutine == 0)
	{
		return 0;
	}
	p = (PUCHAR)ulPsSetCreateThreadNotifyRoutine;
	ulSize = 0x1000;
	for (i=0;i<ulSize;i++,p++)
	{
		if (*(p-4)==0xeb &&
			*(p+8) ==0xe8)
		{
			if (MmIsAddressValidEx(p))
			{
				bFind = TRUE;
				ulAddress = *(PULONG)p;
			}
			break;
		}
	}
	if (!bFind)
	{
		return 0;
	}
	return ulAddress;
}
//
ULONG GetLoadImageNotifyAddr()
{
	//805d1037 eb2a            jmp     nt!PsSetLoadImageNotifyRoutine+0x49 (805d1063)
	//nt!PsSetLoadImageNotifyRoutine+0x1f:
	//805d1039 56              push    esi
	//805d103a bee0495680      mov     esi,offset nt!PspLoadImageNotifyRoutine (805649e0)
	//nt!PsSetLoadImageNotifyRoutine+0x25:
	//805d103f 6a00            push    0
	//805d1041 53              push    ebx
	//805d1042 56              push    esi
	//805d1043 e8fed20300      call    nt!ExCompareExchangeCallBack (8060e346)
	ULONG ulPsSetLoadImageNotifyRoutine;
	PUCHAR p;
	ULONG ulSize;
	ULONG i;
	ULONG ulAddress;
	BOOL bFind = FALSE;
	ulPsSetLoadImageNotifyRoutine = 
		(ULONG)GetExortedFunctionAddress(L"PsSetLoadImageNotifyRoutine");
	if (ulPsSetLoadImageNotifyRoutine == 0)
	{
		return 0;
	}
	p = (PUCHAR)ulPsSetLoadImageNotifyRoutine;
	ulSize = 0x1000;
	for (i=0;i<ulSize;i++,p++)
	{
		if (*(p-4)==0xeb &&
			*(p+8) ==0xe8)
		{
			if (MmIsAddressValidEx(p))
			{
				bFind = TRUE;
				ulAddress = *(PULONG)p;
			}
			break;
		}
	}
	if (!bFind)
	{
		return 0;
	}
	return ulAddress;
}
//
BOOL InitNotifyRoutineAddr()
{
	g_dwCreateProcessNotifyAddr = 
		GetCreateProcessNotifyAddr();
	if (g_dwCreateProcessNotifyAddr == 0)
	{
		return FALSE;
	}
	g_dwCreateThreadNotifyAddr = 
		GetCreateThreadNotifyAddr();
	if (g_dwCreateThreadNotifyAddr == 0)
	{
		return FALSE;
	}
	g_dwSetLoadImageNotifyAddr = GetLoadImageNotifyAddr();
	if (g_dwSetLoadImageNotifyAddr == 0)
	{
		return FALSE;
	}
	return TRUE;
}
//
VOID RemoveNotifyRoutines()
{
	//第一步：YYY=XXX & ~7
	//第二步: *((PULONG)YYY+1) 就是函数地址了
	ULONG ulTmp;
	ULONG ulInternalAddress = 0;
	ULONG i;
	PULONG p;
	LONG uCompareOne;
	LONG uCompareTwo;
	LONG Sub;
	//Sleep(30000);//延时30s
	TpModuleBase = GetKernelModuleBase(g_MyDriverObject,"TesSafe.sys");
	if (TpModuleBase == NULL)
	{
		DbgPrint("cannot find TesSafe.sys\r\n");
		return;
	}
	p = (PULONG)g_dwCreateProcessNotifyAddr;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValid((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			/*判断地址是否在TP的地址空间，是的话就摘掉*/

			if (MmIsAddressValid(TpModuleBase))
			{
				DbgPrint("TpModuleBase:0x%x\r\n",(ULONG)TpModuleBase);
				/*如果差在某个范围内，就说明是TP设置的回调*/
				uCompareOne = (LONG)ulInternalAddress;
				uCompareTwo = (LONG)TpModuleBase;
				Sub = uCompareTwo-uCompareOne;
				if (Sub < 0x400000 && Sub > 0)
				{
					//
					PsSetCreateProcessNotifyRoutine((PCREATE_PROCESS_NOTIFY_ROUTINE)ulInternalAddress,TRUE);
					//DbgPrint("Remove TP CreateProcessNotify\r\n");
				}
				//else
				//{
				//	CodeVprint("CreateProcess uCompareOne != uCompareTwo\r\n");
				//}
			}
		}
	}
	//////////////////////////////////////////////////////////////////////////
	p = (PULONG)g_dwCreateThreadNotifyAddr;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValid((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			/*判断地址是否在TP的地址空间，是的话就摘掉*/

			if (MmIsAddressValid(TpModuleBase))
			{
				//CodeVprint("TpModuleBase:0x%x\r\n",(ULONG)TpModuleBase);
				/*如果差在某个范围内，就说明是TP设置的回调*/
				uCompareOne = (LONG)ulInternalAddress;
				uCompareTwo = (LONG)TpModuleBase;
				Sub = uCompareTwo-uCompareOne;
				if (Sub < 0x400000 && Sub > 0)
				{
					//
					PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)(ulInternalAddress));
					//CodeVprint("Remove TP CreateThreadNotify\r\n");
				}
				//else
				//{
				//	CodeVprint("CreateThread uCompareOne != uCompareTwo\r\n");
				//}
			}
		}
	}
	//////////////////////////////////////////////////////////////////////////
	p = (PULONG)g_dwSetLoadImageNotifyAddr;
	for (i=0;i<8;i++)
	{
		ulTmp = NOTIFY_ADDRESS_CALC_ONE(p[i]);
		if (MmIsAddressValid((PULONG)ulTmp + 1))
		{
			ulInternalAddress = *((PULONG)ulTmp + 1);
			/*判断地址是否在TP的地址空间，是的话就摘掉*/

			if (MmIsAddressValid(TpModuleBase))
			{
				//CodeVprint("TpModuleBase:0x%x\r\n",(ULONG)TpModuleBase);
				/*如果差在某个范围内，就说明是TP设置的回调*/
				uCompareOne = (LONG)ulInternalAddress;
				uCompareTwo = (LONG)TpModuleBase;
				Sub = uCompareTwo-uCompareOne;
				if (Sub < 0x400000 && Sub > 0)
				{
					//
					PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)(ulInternalAddress));
					//CodeVprint("Remove TP LoadImageNotify\r\n");
				}
				//else
				//{
				//	CodeVprint("LoadImage uCompareOne != uCompareTwo\r\n");
				//}
			}
		}
	}
}

