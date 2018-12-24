#ifndef _B_BALKIN_N_
#define _B_BALKIN_N_

#include <Windows.h>
#include <winternalz.h>

typedef struct __balkin_startup_info
{
	STARTUPINFO		si;
	DWORD			extra1;
} balkin_startup_info, *pbalkin_startup_info;

typedef struct __balkin_free_handler
{
	EXCEPTION_REGISTRATION_RECORD edata;
	DWORD nfrees;
	DWORD ptr_array[8];
} balkin_free_handler, *pbalkin_free_handler;

static long g_balkin_instance = 0;
static DWORD g_tlsindex = 0;

#define BSI_VERIFY_CONST 0x8f8f8f8fL

#endif
