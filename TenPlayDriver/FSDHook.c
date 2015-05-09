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
//	if (*p1 == L'\\')//说明倒数第一个就是反斜线
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
//	//变量的声明
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
//	+0x018 FileObject       : Ptr32 _FILE_OBJECT		//这里有一个文件对象
//	+0x01c CompletionRoutine : Ptr32     long 
//	+0x020 Context          : Ptr32 Void
//	*/
//	//是否为空
//	if (IoStackLocation==NULL)
//	{
//		//我们就直接调用原始
//		//这里就是刚才为什么要保存原始函数的原因
//		return s_pfnOriginCreateDispatch(DeviceObject,Irp);
//	}
//	//取出这个文件对象成员
//	//我们关心的是  +0x030 FileName         : _UNICODE_STRING
//	FileObject=IoStackLocation->FileObject;
//	if (FileObject==NULL)
//	{
//		//如果文件对象为空，那么我们就直接返回原始函数
//		return s_pfnOriginCreateDispatch(DeviceObject,Irp);
//	}
//	//所有的操作都要在IRQL PASSIVE_LEVEL等级下进行，why？
//	//_stricmp 这个函数，只能在PASSIVE_LEVEL这个级别下运行，所以，我们要做个IRQL的等级判断
//	if (KeGetCurrentIrql() == PASSIVE_LEVEL)
//	{
//		//验证unicode是否可以访问
//		/*
//		kd> dt_UNICODE_STRING
//		nt!_UNICODE_STRING
//		+0x000 Length           : Uint2B
//		+0x002 MaximumLength    : Uint2B
//		+0x004 Buffer           : Ptr32 Uint2B //判断效验这个是否可以访问
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
//	//调用原始函数
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
//	//接着调用内核api函数，从名字获得对象
//	//对象--》handle handle--》对象
//	nStatus = ObReferenceObjectByName(&uNtfsDevice, 
//		OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,
//		NULL,
//		0,
//		*IoDriverObjectType, //这个参数指明DriverObject
//		KernelMode,				//内核模式
//		NULL,
//		&s_NtfsDriverObj);
//	if (!NT_SUCCESS(nStatus))
//	{
//		return;
//	}
//	ObDereferenceObject(s_NtfsDriverObj);
//	//
//	//我们要保存原始地址。
//	s_pfnOriginCreateDispatch = (PFN_NTFSCREATEDISPATCH)(s_NtfsDriverObj->MajorFunction[IRP_MJ_CREATE]);
//
//	//开始Hook
//	//我们首先要了解，为什么要禁止写保护。ssdt，shadowssdt，eat，iat内容他们只是只读内存
//	//而在这里呢，这个数组是可写。
//	//我们就开始HOOK
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