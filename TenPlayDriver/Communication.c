#include "Communication.h"

#define MY_DEVICE_NAME		L"\\Device\\NiviaEx"
#define MY_SYMBOL_NAME		L"\\??\\HelloDDK"
static INLINE_HOOK_INFO ci = {0};
extern LONG g_HookReferCnt[MAX_REFER_CNT];


/* ͨ��IRP�ַ� */
NTSTATUS IoDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//

/* ��Ӧ�ò�ͨ��IRP */
NTSTATUS IoHelloDDKDispatch(PDEVICE_OBJECT pDeviceObject,PIRP pIrp)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	switch(code)
	{
	case CTRL_START_PROTECT:
		{

			if(InitOwnProcess(PsGetCurrentProcess()) == STATUS_SUCCESS)
			{
				avPrint("InitOwnProcess success...");
				//HookIoCreateFile();
				//HookObReferenceObjectByHandle();
				HookKiFastCallEntryMiddle();
				HideOwnProcess();
				avPrint("CTRL_START_PROTECT ok!");
			}
		}
		break;
	case CTRL_STOP_PROTECT:
		{
			RecoverHideProcess();
			//UnhookPsCallImageNotifyRoutines();
			//UnhookIoCreateFile();
			UnhookKiFastCallEntryMiddle();
			//UnhookObReferenceObjectByHandle();
			//
			WaitReferCntSubToZero();
			avPrint("CTRL_STOP_PROTECT ok!");
		}
		break;
	case CTRL_REMOVE_NOTIFY:
		{
			RemoveNotifyRoutines();
			avPrint("CTRL_REMOVE_NOTIFY ok!");
		}
		break;
	}
	pIrp->IoStatus.Status=STATUS_SUCCESS;
	IoCompleteRequest(pIrp,IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
/* �����豸���� */
NTSTATUS CreateDevice(PDRIVER_OBJECT pDriverObject)
{
	NTSTATUS       st					= STATUS_SUCCESS;
	UNICODE_STRING DeviceName			= {0};
	UNICODE_STRING SymLinkName			= {0};	
	PDEVICE_OBJECT pDeviceObject;
	RtlInitUnicodeString(&DeviceName, MY_DEVICE_NAME);
	st=IoCreateDevice(
		pDriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		TRUE,
		&pDeviceObject);
	if (!NT_SUCCESS(st))
	{
		avPrint("CreateDevice failed!");
		return st;
	}
	pDeviceObject->Flags|=DO_BUFFERED_IO;
	avPrint("CreateDevice success!");
	RtlInitUnicodeString(&SymLinkName,MY_SYMBOL_NAME);
	st=IoCreateSymbolicLink(&SymLinkName,&DeviceName);
	if (!NT_SUCCESS(st))
	{
		IoDeleteDevice(pDeviceObject);
		avPrint("CreateSymLinkName failed!");
		return st;
	}
	avPrint("CreateSymLinkName success!");
	return st;
}
/*ɾ���豸����*/
VOID DeleteDevice(PDEVICE_OBJECT DeviceObject)
{
	UNICODE_STRING SymLinkName			= {0};
	RtlInitUnicodeString(&SymLinkName,MY_SYMBOL_NAME);
	IoDeleteSymbolicLink(&SymLinkName);
	IoDeleteDevice(DeviceObject);
	avPrint("Delete Device and SymLinkName success!");
	return;
}
///////////////////////////////////////////////////////////////////
//R3�µĿ�����ַ�������ʼ����readfile
//NTSTATUS 
//__stdcall
//avCommandDispatcher (
//	__in HANDLE FileHandle,
//	__in_opt HANDLE Event,
//	__in_opt PIO_APC_ROUTINE ApcRoutine,
//	__in_opt PVOID ApcContext,
//	__out PIO_STATUS_BLOCK IoStatusBlock,
//	__out_bcount(Length) PVOID Buffer,
//	__in ULONG Length,
//	__in_opt PLARGE_INTEGER ByteOffset,
//	__in_opt PULONG Key
//	)
//{
//	ULONG dwCtrlCode = (ULONG)FileHandle;
//	PFN_NTREADFILE pfnNtReadFile = (PFN_NTREADFILE)ci.lpHookZoneAddr;
//	if (CTRL_SUCCESS(dwCtrlCode))
//	{
//		//�жϿ�����
//		if (dwCtrlCode == CTRL_PRINT_TEST)
//		{
//			//��ӡ����
//			avPrint("CTRL_PRINT_TEST success...");
//			
//		}
//		else if (dwCtrlCode == CTRL_START_PROTECT)
//		{
//			HookPsCallImageNotifyRoutines();
//			PatchReloadPspCreateThread();
//			HookIoCreateFile();
//			HookKiFastCallEntryMiddle();
//			HideOwnProcess();
//		}
//		else if (dwCtrlCode == CTRL_STOP_PROTECT)
//		{
//
//			RecoverHideProcess();
//			UnhookPsCallImageNotifyRoutines();
//
//			UnhookIoCreateFile();
//			UnhookKiFastCallEntryMiddle();
//		}
//		else if (dwCtrlCode == CTRL_KILL_DXF)
//		{
//			KillDxfProcess();
//			ReplaceDxfFiles();
//		}
//		return STATUS_UNSUCCESSFUL;
//	}
//	//���ǿ�����
//	return pfnNtReadFile(FileHandle,
//		Event,
//		ApcRoutine,
//		ApcContext,
//		IoStatusBlock,
//		Buffer,
//		Length,
//		ByteOffset,
//		Key);
//}
////
//_declspec(naked) VOID CommHookZone()
//{
//	
//	NOP_PROC;
//	__asm jmp [ci.lpRetAddr];
//}
////ͨ��readfile����ͨ��
//BOOL InitCommunication()
//{
//	//NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
//	//BOOL bRetOk = FALSE;
//	ci.lpOriginAddr = GetExortedFunctionAddress(L"NtReadFile");
//	if (!ci.lpOriginAddr)
//	{
//		return FALSE;
//	}
//	ci.lpHookZoneAddr = CommHookZone;
//	ci.lpNewAddr = (PVOID)avCommandDispatcher;
//	ci.dwPatchLength = 0;
//	ci.lpRetAddr = NULL;
//	return HookFunctionByHeaderAddress(&ci);
//}
////ɾ��ͨ��
//VOID DeleteCommunication()
//{
//	if (ci.lpRetAddr)
//	{
//		//����ܻ�ȡ�����ص�ַ��˵��ͨ�ųɹ���
//		UnHookFunctionByHeaderAddress(&ci);
//	}
//}