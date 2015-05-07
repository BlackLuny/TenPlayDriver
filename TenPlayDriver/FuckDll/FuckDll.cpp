// FuckDll.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "FuckDll.h"
#include "stdio.h"

// 这是导出变量的一个示例
FUCKDLL_API int nFuckDll=0;

// 这是导出函数的一个示例。
FUCKDLL_API int fnFuckDll(void)
{
	return 42;
}

// 这是已导出类的构造函数。
// 有关类定义的信息，请参阅 FuckDll.h
CFuckDll::CFuckDll()
{
	return;
}

void trace0(char *fmt, ...)
{
	char out[1024];
	va_list body;
	va_start(body, fmt);
	vsprintf(out, fmt, body); // 译注：格式化输入的字符串 fmtt
	va_end(body);               //       到输出字符串 ou
	OutputDebugStringA(out); // 译注：输出格式化后的字符串到调试器
}

VOID RemoveTheFlags(KBDLLHOOKSTRUCT * pKbdHook)
{
	pKbdHook->flags &= ~0x00000002;//LLKHF_LOWER_IL_INJECTED
	pKbdHook->flags &= ~0x00000010;//LLKHF_INJECTED
	//pKbdHook->flags &= ~0x00000001;
	//trace0("after handle pKbdHook->flags : 0x%x\n",pKbdHook->flags);
	//OutputDebugStringA("after handle pKbdHook->flags : 0x%8x\n",pKbdHook->flags);
}

LRESULT CALLBACK LowLevelKeyboardProc(
	_In_  int nCode,
	_In_  WPARAM wParam,
	_In_  LPARAM lParam
	)
{
	KBDLLHOOKSTRUCT * pKbdHook = NULL;
	if (nCode == HC_ACTION)
	{
		if (wParam == WM_KEYDOWN || wParam == WM_KEYUP)
		{
			pKbdHook = (KBDLLHOOKSTRUCT *)lParam;
			//去除俩标志
			//OutputDebugStringA("before handle pKbdHook->flags : 0x%8x\n",pKbdHook->flags);
			//trace0("before handle pKbdHook->flags : 0x%x\n",pKbdHook->flags);
			RemoveTheFlags(pKbdHook);
		}
	}
	return CallNextHookEx(NULL,nCode,wParam,lParam);
}
HHOOK g_idHook = NULL;

extern "C" FUCKDLL_API void UnloadFuck(void)
{
	if (g_idHook != NULL)
	{
		UnhookWindowsHookEx(g_idHook);
	}

}

extern "C" FUCKDLL_API  void SetFuck(void)
{
	//HHOOK WINAPI SetWindowsHookEx(
	//	_In_  int idHook,
	//	_In_  HOOKPROC lpfn,
	//	_In_  HINSTANCE hMod,
	//	_In_  DWORD dwThreadId
	//	);
	g_idHook = SetWindowsHookEx(WH_KEYBOARD_LL,
		LowLevelKeyboardProc,
		GetModuleHandle(L"FuckDll.dll"),
		0);
}
