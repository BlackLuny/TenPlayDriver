#pragma once
#include "struct.h"
#include "InlineHook.h"
#include "Ntos.h"
#include "HookPort.h"



typedef NTSTATUS  ( __stdcall *PFN_OBREFERENCEOBJECTBYHANDLE)(                                      
	IN HANDLE Handle,                                           
	IN ACCESS_MASK DesiredAccess,                               
	IN POBJECT_TYPE ObjectType OPTIONAL,                        
	IN KPROCESSOR_MODE AccessMode,                              
	OUT PVOID *Object,                                          
	OUT POBJECT_HANDLE_INFORMATION HandleInformation OPTIONAL   
	);     
//////////////////////////////////////////////////////////////////////////
VOID HookObReferenceObjectByHandle();
VOID UnhookObReferenceObjectByHandle();