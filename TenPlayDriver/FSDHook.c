#include "FSDHook.h"

static BOOL s_bHooked= FALSE;
static INLINE_HOOK_INFO hi = {0};
//extern SERVICE_FUNCTION_ADDR g_ServiceFuncAddr;
extern OWNPROCESS_INFO g_OwnInfo;
extern CHAR OwnDmDll[30];
extern CHAR OwnProcessName[30];
extern WCHAR wOwnProcessName[30];
extern WCHAR wOwnDmDll[30];
//
extern LONG g_HookReferCnt[MAX_REFER_CNT];
//#define  NTFS_DEVICE_NAME	L"\\FileSystem\\Ntfs"

//////////////////////////////////////////////////////////////////////////
NTSTATUS
	NewIoCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG Disposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength,
	IN CREATE_FILE_TYPE CreateFileType,
	IN PVOID ExtraCreateParameters OPTIONAL,
	IN ULONG Options
	)
{
	NTSTATUS nStatus = STATUS_UNSUCCESSFUL;
	InterlockedIncrement(&g_HookReferCnt[20]);
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
					 nStatus = STATUS_UNSUCCESSFUL;
					 goto _CleanUp;
				 }
			 }
		 }
	 }

	nStatus = ((PFN_IOCREATEFILE)hi.lpHookZoneAddr)(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		Disposition,
		CreateOptions,
		EaBuffer,
		EaLength,
		CreateFileType,
		ExtraCreateParameters,
		Options);
_CleanUp:
	InterlockedDecrement(&g_HookReferCnt[20]);
	return nStatus;
}
__declspec(naked) VOID IoCreateFileZone()
{
	NOP_PROC;
	__asm jmp [hi.lpRetAddr];
}
//test
VOID HookIoCreateFile()
{
	PVOID lpIoCreateFile = NULL;
	lpIoCreateFile = GetExortedFunctionAddress(L"IoCreateFile");
	if (!lpIoCreateFile)
	{
		return;
	}
	hi.lpHookZoneAddr = IoCreateFileZone;
	hi.lpNewAddr = NewIoCreateFile;
	hi.lpOriginAddr = lpIoCreateFile;
	hi.dwPatchLength = 0;
	hi.lpRetAddr = NULL;
	if (HookFunctionByHeaderAddress(&hi))
	{
		s_bHooked = TRUE;
	}
}
VOID UnhookIoCreateFile()
{
	if (s_bHooked)
	{
		UnHookFunctionByHeaderAddress(&hi);
	}
}

//BOOL GetLastDirNameFromPath(PUNICODE_STRING pUniPath,WCHAR *pLastDir)
//{
//	USHORT wLen = pUniPath->Length;
//	USHORT wMaxLen = pUniPath->MaximumLength;
//	wchar_t *p1,*p2;
//	//if (wcslen(pUniPath->Buffer) < wLen/sizeof(WCHAR))
//	//{
//	//	avPrint("not a good unicodestring");
//	//}
//	p1 = p2 = pUniPath->Buffer + wLen/sizeof(WCHAR) -1;
//	if (*p1 == L'\\')//˵��������һ�����Ƿ�б��
//	{
//		--p1;
//		--p2;
//	}
//	while(*p1 != L'\\')
//	{
//		p1--;
//		if (p1 == pUniPath->Buffer)
//		{
//			break;
//		}
//	}
//	if (*p1 == L'\\')
//	{
//		RtlCopyMemory(pLastDir,p1+1,(p2 - p1)*sizeof(WCHAR));
//		return TRUE;
//	}
//	return FALSE;
//	//memcpy(pLastDir,p1+1,(p2 - p1)*sizeof(wchar_t));
//
//}
//////////////////////////////////////////////////////////////////////////

//NTSTATUS NtfsCreateDispatchHook(
//	IN PDEVICE_OBJECT		DeviceObject,
//	IN PIRP					Irp
//	)
//{
//	//����������
//	NTSTATUS Status							=STATUS_UNSUCCESSFUL;
//	PIO_STACK_LOCATION IoStackLocation		= NULL;
//	PFILE_OBJECT FileObject					= NULL;
//	PEPROCESS Eprocess						= NULL;
//	CHAR *ImageFileName						= NULL;
//	WCHAR *pLastDir							= NULL;
//	IoStackLocation=IoGetCurrentIrpStackLocation(Irp);
//	/*
//	kd> dt_IO_STACK_LOCATION
//	nt!_IO_STACK_LOCATION
//	+0x000 MajorFunction    : UChar
//	+0x001 MinorFunction    : UChar
//	+0x002 Flags            : UChar
//	+0x003 Control          : UChar
//	+0x004 Parameters       : __unnamed
//	+0x014 DeviceObject     : Ptr32 _DEVICE_OBJECT
//	+0x018 FileObject       : Ptr32 _FILE_OBJECT		//������һ���ļ�����
//	+0x01c CompletionRoutine : Ptr32     long 
//	+0x020 Context          : Ptr32 Void
//	*/
//	//�Ƿ�Ϊ��
//	if (IoStackLocation==NULL)
//	{
//		//���Ǿ�ֱ�ӵ���ԭʼ
//		//������Ǹղ�ΪʲôҪ����ԭʼ������ԭ��
//		return s_pfnOriginCreateDispatch(DeviceObject,Irp);
//	}
//	//ȡ������ļ������Ա
//	//���ǹ��ĵ���  +0x030 FileName         : _UNICODE_STRING
//	FileObject=IoStackLocation->FileObject;
//	if (FileObject==NULL)
//	{
//		//����ļ�����Ϊ�գ���ô���Ǿ�ֱ�ӷ���ԭʼ����
//		return s_pfnOriginCreateDispatch(DeviceObject,Irp);
//	}
//	//���еĲ�����Ҫ��IRQL PASSIVE_LEVEL�ȼ��½��У�why��
//	//_stricmp ���������ֻ����PASSIVE_LEVEL������������У����ԣ�����Ҫ����IRQL�ĵȼ��ж�
//	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
//	{
//		//��֤unicode�Ƿ���Է���
//		/*
//		kd> dt_UNICODE_STRING
//		nt!_UNICODE_STRING
//		+0x000 Length           : Uint2B
//		+0x002 MaximumLength    : Uint2B
//		+0x004 Buffer           : Ptr32 Uint2B //�ж�Ч������Ƿ���Է���
//		*/
//		ImageFileName = PsGetProcessImageFileName(PsGetCurrentProcess());
//		if (_stricmp(ImageFileName,"explorer.exe") == 0)
//		{
//			//avPrint("explorer.exe call...");
//			if (ValidateUnicodeString( &FileObject->FileName))
//			{
//				//DbgPrint("FileName : %wZ\n",&FileObject->FileName);
//				if (g_OwnInfo.uOwnProcessFullPath.Buffer)
//				{
//					pLastDir = g_OwnInfo.uOwnProcessFullPath.Buffer;
//					//\\??\\c:\\//
//						if(wcsstr(FileObject->FileName.Buffer,pLastDir + 6))
//						{
//							//find
//							Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
//							return STATUS_UNSUCCESSFUL;
//						}
//					//if(GetLastDirNameFromPath(&g_OwnInfo.uOwnProcessFullPath,wszLastDir))
//					//{
//					//	//DbgPrint("FileName : %ws\n",wszLastDir);
//
//					//	if(wcsstr(FileObject->FileName.Buffer,wszLastDir))
//					//	{
//					//		//find
//					//		return STATUS_UNSUCCESSFUL;
//					//	}
//
//					//}
//
//				}
//			}
//		}
//	}
////_FunctionRet:
//	//����ԭʼ����
//	Status=s_pfnOriginCreateDispatch(DeviceObject,Irp);
//	return Status;
//}
//VOID HookNtfsDispatchCreate()
//{
//    NTSTATUS nStatus				= STATUS_UNSUCCESSFUL;
//	UNICODE_STRING uNtfsDevice		= {0};
//
//	RtlInitUnicodeString(&uNtfsDevice,NTFS_DEVICE_NAME);
//
//	//���ŵ����ں�api�����������ֻ�ö���
//	//����--��handle handle--������
//	nStatus = ObReferenceObjectByName(&uNtfsDevice, 
//		OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
//		NULL,
//		0,
//		*IoDriverObjectType, //�������ָ��DriverObject
//		KernelMode,				//�ں�ģʽ
//		NULL,
//		&s_NtfsDriverObj);
//	if (!NT_SUCCESS(nStatus))
//	{
//		return;
//	}
//	ObDereferenceObject(s_NtfsDriverObj);
//	//
//	//����Ҫ����ԭʼ��ַ��
//	s_pfnOriginCreateDispatch = (PFN_NTFSCREATEDISPATCH)(s_NtfsDriverObj->MajorFunction[IRP_MJ_CREATE]);
//
//	//��ʼHook
//	//��������Ҫ�˽⣬ΪʲôҪ��ֹд������ssdt��shadowssdt��eat��iat��������ֻ��ֻ���ڴ�
//	//���������أ���������ǿ�д��
//	//���ǾͿ�ʼHOOK
//	InterlockedExchange((LONG*)&(s_NtfsDriverObj->MajorFunction[IRP_MJ_CREATE]),(LONG)NtfsCreateDispatchHook);
//	//DriverObj->MajorFunction[IRP_MJ_CREATE] = NtfsCreateDispatchHook;
//	s_bHooked = TRUE;
//	return;
//}
//
//VOID UnhookNtfsDispatchCreate()
//{
//	if (s_bHooked)
//	{
//		InterlockedExchange((LONG*)&(s_NtfsDriverObj->MajorFunction[IRP_MJ_CREATE]),(LONG)s_pfnOriginCreateDispatch);
//	}
//}