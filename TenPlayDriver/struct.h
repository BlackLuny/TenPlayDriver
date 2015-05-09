/***************************************************************************************
* AUTHOR : vLink
* DATE   : 2015-4-12
* MODULE : struct.h
* 
* Command: 
*   驱动的头文件
*
* Description:
*   定义一些常量,避免重复劳动; 您可以在此添加需要的函数/结构体
*
****************************************************************************************

Copyright (C) 2010 vLink.
****************************************************************************************/

#pragma once

#include <ntddk.h> 
/*#include <ntdef.h>*/
#include <ntimage.h>// This is the include file that describes all image structures.
/***************************************************************/
#define SEC_IMAGE    0x01000000
#define NOP_PROC		__asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90\
						__asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 __asm  _emit 0x90 

typedef long LONG;
typedef unsigned char  BOOL, *PBOOL;
typedef unsigned char  BYTE, *PBYTE;
typedef unsigned long  DWORD, *PDWORD;
typedef unsigned short WORD, *PWORD;

typedef void  *HMODULE;
typedef long NTSTATUS, *PNTSTATUS;
typedef unsigned long DWORD;
typedef DWORD * PDWORD;
typedef unsigned long ULONG;
typedef unsigned long ULONG_PTR;
typedef ULONG *PULONG;
typedef ULONG UINT;
typedef unsigned short WORD;
typedef unsigned char BYTE; 
typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef void *PVOID;
typedef BYTE BOOLEAN;

//----------------------------------------------------
typedef struct _VERSION_OFFSET{
	ULONG dwImageName;
	ULONG dwProcessId;
	ULONG dwNtFullPath;

}VERSION_OFFSET,*PVERSION_OFFSET;
//----------------------------------------------------
typedef struct _AUX_ACCESS_DATA {
	PPRIVILEGE_SET PrivilegesUsed;
	GENERIC_MAPPING GenericMapping;
	ACCESS_MASK AccessesToAudit;
	ACCESS_MASK MaximumAuditMask;
	ULONG Unknown[41];
} AUX_ACCESS_DATA, *PAUX_ACCESS_DATA;

//////////////////////////////////////////////////////////////////////////
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct {
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		struct {
			ULONG TimeDateStamp;
		};
		struct {
			PVOID LoadedImports;
		};
	};
	PVOID EntryPointActivationContext;

	PVOID PatchInformation;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
/***************************************************************/
typedef struct _SERVICE_DESCRIPTOR_TABLE {
	/*
	* Table containing cServices elements of pointers to service handler
	* functions, indexed by service ID.
	*/
	PULONG   ServiceTable;
	/*
	* Table that counts how many times each service is used. This table
	* is only updated in checked builds.
	*/
	PULONG  CounterTable;
	/*
	* Number of services contained in this table.
	*/
	ULONG   TableSize;
	/*
	* Table containing the number of bytes of parameters the handler
	* function takes.
	*/
	PUCHAR  ArgumentTable;
} SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE;
//声明系统描述表
extern PSERVICE_DESCRIPTOR_TABLE    KeServiceDescriptorTable;
//////////////////////////////////////////////////////////////////////////
typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	BOOLEAN UseDefaultObject;
	BOOLEAN CaseInsensitive;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	BOOLEAN MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	PVOID OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	PVOID ParseProcedure;
	PVOID SecurityProcedure;
	PVOID QueryNameProcedure;
	PVOID OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, *POBJECT_TYPE_INITIALIZER;
//
typedef struct _MMPTE_SOFTWARE {
	ULONG Valid : 1;
	ULONG PageFileLow : 4;
	ULONG Protection : 5;
	ULONG Prototype : 1;
	ULONG Transition : 1;
	ULONG PageFileHigh : 20;
} MMPTE_SOFTWARE;

typedef struct _MMPTE_TRANSITION {
	ULONG Valid : 1;
	ULONG Write : 1;
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Protection : 5;
	ULONG Prototype : 1;
	ULONG Transition : 1;
	ULONG PageFrameNumber : 20;
} MMPTE_TRANSITION;

typedef struct _MMPTE_PROTOTYPE {
	ULONG Valid : 1;
	ULONG ProtoAddressLow : 7;
	ULONG ReadOnly : 1;  // if set allow read only access.
	ULONG WhichPool : 1;
	ULONG Prototype : 1;
	ULONG ProtoAddressHigh : 21;
} MMPTE_PROTOTYPE;

typedef struct _MMPTE_HARDWARE {
	ULONG Valid : 1;
	ULONG Write : 1;       // UP version
	ULONG Owner : 1;
	ULONG WriteThrough : 1;
	ULONG CacheDisable : 1;
	ULONG Accessed : 1;
	ULONG Dirty : 1;
	ULONG LargePage : 1;
	ULONG Global : 1;
	ULONG CopyOnWrite : 1; // software field
	ULONG Prototype : 1;   // software field
	ULONG reserved : 1;    // software field
	ULONG PageFrameNumber : 20;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE;

typedef struct _MMPTE {
	union  {
		ULONG Long;
		MMPTE_HARDWARE Hard;
		MMPTE_PROTOTYPE Proto;
		MMPTE_SOFTWARE Soft;
		MMPTE_TRANSITION Trans;
	} u;
} MMPTE, *PMMPTE;

typedef struct _MMPTE_SOFTWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG PageFileLow : 4;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG Unused : 20;
	ULONGLONG PageFileHigh : 32;
} MMPTE_SOFTWARE_PAE;

typedef struct _MMPTE_TRANSITION_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Prototype : 1;
	ULONGLONG Transition : 1;
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG Unused : 28;
} MMPTE_TRANSITION_PAE;

typedef struct _MMPTE_PROTOTYPE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Unused0: 7;
	ULONGLONG ReadOnly : 1;  // if set allow read only access.  LWFIX: remove
	ULONGLONG Unused1: 1;
	ULONGLONG Prototype : 1;
	ULONGLONG Protection : 5;
	ULONGLONG Unused: 16;
	ULONGLONG ProtoAddress: 32;
} MMPTE_PROTOTYPE_PAE;

typedef struct _MMPTE_HARDWARE_PAE {
	ULONGLONG Valid : 1;
	ULONGLONG Write : 1;        // UP version
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1; // software field
	ULONGLONG Prototype : 1;   // software field
	ULONGLONG reserved0 : 1;  // software field
	ULONGLONG PageFrameNumber : 24;
	ULONGLONG reserved1 : 28;  // software field
} MMPTE_HARDWARE_PAE, *PMMPTE_HARDWARE_PAE;

typedef struct _MMPTE_PAE {
	union  {
		LARGE_INTEGER Long;
		MMPTE_HARDWARE_PAE Hard;
		MMPTE_PROTOTYPE_PAE Proto;
		MMPTE_SOFTWARE_PAE Soft;
		MMPTE_TRANSITION_PAE Trans;
	} u;
} MMPTE_PAE;

typedef MMPTE_PAE *PMMPTE_PAE;

#define PTE_BASE    0xC0000000
#define PDE_BASE    0xC0300000
#define PDE_BASE_PAE 0xc0600000

#define MiGetPdeAddress(va)  ((MMPTE*)(((((ULONG)(va)) >> 22) << 2) + PDE_BASE))
#define MiGetPteAddress(va) ((MMPTE*)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))

#define MiGetPdeAddressPae(va)   ((PMMPTE_PAE)(PDE_BASE_PAE + ((((ULONG)(va)) >> 21) << 3)))
#define MiGetPteAddressPae(va)   ((PMMPTE_PAE)(PTE_BASE + ((((ULONG)(va)) >> 12) << 3)))

#define MM_ZERO_PTE 0
#define MM_ZERO_KERNEL_PTE 0


#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7
#define MM_NOCACHE             8
#define PAE_ON (1<<5)
typedef enum VALIDITY_CHECK_STATUS{
	VCS_INVALID,
	VCS_VALID,
	VCS_TRANSITION,
	VCS_PAGEDOUT,
	VCS_DEMANDZERO,
	VCS_PROTOTYPE
}VALIDITY_CHECK_STATUS;
//
//
// System Information Classes.
//

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,             // obsolete...delete
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

//
// System Information Structures.
//

// begin_winnt
#define TIME_ZONE_ID_UNKNOWN  0
#define TIME_ZONE_ID_STANDARD 1
#define TIME_ZONE_ID_DAYLIGHT 2
// end_winnt

typedef struct _SYSTEM_VDM_INSTEMUL_INFO {
	ULONG SegmentNotPresent ;
	ULONG VdmOpcode0F       ;
	ULONG OpcodeESPrefix    ;
	ULONG OpcodeCSPrefix    ;
	ULONG OpcodeSSPrefix    ;
	ULONG OpcodeDSPrefix    ;
	ULONG OpcodeFSPrefix    ;
	ULONG OpcodeGSPrefix    ;
	ULONG OpcodeOPER32Prefix;
	ULONG OpcodeADDR32Prefix;
	ULONG OpcodeINSB        ;
	ULONG OpcodeINSW        ;
	ULONG OpcodeOUTSB       ;
	ULONG OpcodeOUTSW       ;
	ULONG OpcodePUSHF       ;
	ULONG OpcodePOPF        ;
	ULONG OpcodeINTnn       ;
	ULONG OpcodeINTO        ;
	ULONG OpcodeIRET        ;
	ULONG OpcodeINBimm      ;
	ULONG OpcodeINWimm      ;
	ULONG OpcodeOUTBimm     ;
	ULONG OpcodeOUTWimm     ;
	ULONG OpcodeINB         ;
	ULONG OpcodeINW         ;
	ULONG OpcodeOUTB        ;
	ULONG OpcodeOUTW        ;
	ULONG OpcodeLOCKPrefix  ;
	ULONG OpcodeREPNEPrefix ;
	ULONG OpcodeREPPrefix   ;
	ULONG OpcodeHLT         ;
	ULONG OpcodeCLI         ;
	ULONG OpcodeSTI         ;
	ULONG BopCount          ;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;
//
//kd> dt _KAPC_STATE
//	nt!_KAPC_STATE
//	+0x000 ApcListHead      : [2] _LIST_ENTRY
//	+0x010 Process          : Ptr32 _KPROCESS
//	+0x014 KernelApcInProgress : UChar
//	+0x015 KernelApcPending : UChar
//	+0x016 UserApcPending   : UChar
#pragma pack(push ,1)
typedef struct _KAPC_STATE{
	LIST_ENTRY ApcListHead[2];//      : [2] _LIST_ENTRY
	struct _KPROCESS *Process;//          : Ptr32 _KPROCESS
	UCHAR KernelApcInProgress;
	UCHAR KernelApcPending;// : UChar
	UCHAR UserApcPending;//   : UChar
}KAPC_STATE,*PKAPC_STATE;


typedef struct _HANDLE_TABLE_ENTRY_INFO {
	ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY {
	union {
		PVOID                       Object;
		ULONG                       ObAttributes;
		PHANDLE_TABLE_ENTRY_INFO    InfoTable;
		ULONG                       Value;
	};
	union {
		ULONG                       GrantedAccess;
		USHORT                      GrantedAccessIndex;
		LONG                        NextFreeTableEntry;
	};
	USHORT                          CreatorBackTraceIndex;
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
typedef struct _HANDLE_TABLE {

	//
	//  A set of flags used to denote the state or attributes of this
	//  particular handle table
	//

	ULONG Flags;

	//
	//  The number of handle table entries in use.
	//

	LONG HandleCount;

	//
	//  A pointer to the top level handle table tree node.
	//

	PHANDLE_TABLE_ENTRY **Table;

	//
	//  The process who is being charged quota for this handle table and a
	//  unique process id to use in our callbacks
	//

	struct _EPROCESS *QuotaProcess;
	HANDLE UniqueProcessId;

	//
	//  This is a singly linked list of free table entries.  We don't actually
	//  use pointers, but have each store the index of the next free entry
	//  in the list.  The list is managed as a lifo list.  We also keep track
	//  of the next index that we have to allocate pool to hold.
	//

	LONG FirstFreeTableEntry;
	LONG NextIndexNeedingPool;

	//
	//  This is the lock used to protect the fields in the record, and the
	//  handle table tree in general.  Individual handle table entries that are
	//  not free have their own lock
	//

	ERESOURCE HandleTableLock;

	//
	//  The list of global handle tables.  This field is protected by a global
	//  lock.
	//

	LIST_ENTRY HandleTableList;

	//
	//  The following field is used to loosely synchronize thread contention
	//  on a handle.  If a thread wants to wait for a handle to be unlocked
	//  it will wait on this event with a short timeout.  Any handle unlock
	//  operation will pulse this event if there are threads waiting on it
	//

	KEVENT HandleContentionEvent;
} HANDLE_TABLE, *PHANDLE_TABLE;	
#pragma pack(pop)