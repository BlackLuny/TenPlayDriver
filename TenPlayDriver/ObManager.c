#include "ObManager.h"

extern LONG g_HookReferCnt[MAX_REFER_CNT];
static INLINE_HOOK_INFO s_ObjHookInfo={0};

//////////////////////////////////////////////////////////////////////////
extern SERVICE_FUNCTION_ADDR g_ServiceFuncAddr;
extern OWNPROCESS_INFO g_OwnInfo;
extern KERNEL_FUNCTION_INFO g_KernelFuncAddr;

//////////////////////////////////////////////////////////////////////////

NTSTATUS                                                        
	NewObReferenceObjectByHandle(                                      
	IN HANDLE Handle,                                           
	IN ACCESS_MASK DesiredAccess,                               
	IN POBJECT_TYPE ObjectType OPTIONAL,                        
	IN KPROCESSOR_MODE AccessMode,                              
	OUT PVOID *Object,                                          
	OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
	)
{
	NTSTATUS st			= STATUS_UNSUCCESSFUL;
	InterlockedIncrement(&g_HookReferCnt[7]);


	st = ((PFN_OBREFERENCEOBJECTBYHANDLE)(g_KernelFuncAddr.dwReloadObReferenceObjectByHandle))(Handle,
		DesiredAccess,
		ObjectType,
		AccessMode,
		Object,
		HandleInformation);
	if (!NT_SUCCESS(st))
	{
		goto _CleanUp;
	}
	//success
	//ObDereferenceObject(Object);
	if (IsFromGameProcess())
	{
		if (ObjectType == *PsProcessType)
		{
			if ((PEPROCESS)Object == g_OwnInfo.pProtectedProcess)
			{
				ObDereferenceObject(Object);
				Object = NULL;
				st = STATUS_INVALID_PARAMETER;
				goto _CleanUp;
			}
		}
	}




_CleanUp:
	InterlockedDecrement(&g_HookReferCnt[7]);
	return st;
}
__declspec(naked) VOID HookObReferenceObjectByHandleZone()
{
	NOP_PROC;
	__asm jmp [s_ObjHookInfo.lpRetAddr]
}

VOID HookObReferenceObjectByHandle()
{
	s_ObjHookInfo.lpOriginAddr		= (PVOID)g_KernelFuncAddr.dwObReferenceObjectByHandle;
	s_ObjHookInfo.lpHookZoneAddr	= HookObReferenceObjectByHandleZone;
	s_ObjHookInfo.lpNewAddr			= (PVOID)NewObReferenceObjectByHandle;
	s_ObjHookInfo.lpRetAddr			= NULL;
	s_ObjHookInfo.dwPatchLength		= 0;
	HookFunctionByHeaderAddress(&s_ObjHookInfo);
}
//
VOID UnhookObReferenceObjectByHandle()
{
	if (s_ObjHookInfo.lpRetAddr)
	{
		UnHookFunctionByHeaderAddress(&s_ObjHookInfo);
	}
}