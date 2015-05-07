#ifndef _LDASM_
#define _LDASM_
#include "struct.h"
ULONG __fastcall SizeOfCode(void *Code, unsigned char **pOpcode);

ULONG __fastcall SizeOfProc(void *Proc);

char __fastcall IsRelativeCmd(unsigned char *pOpcode);

#endif