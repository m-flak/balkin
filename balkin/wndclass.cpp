#include "wndclass.h"
#include "unique_persist.h"
#include "balkin.hpp"

/* I forgot what this wuz even meant to do. It doesn't werk right and is ultra confusing.
 * * Certain states of mind do not have programmin' in mind -.O
 */
extern "C" static bool APIENTRY checkuuidunique(uniqpers_idbox *uuidlist)
{
		bool isuniq = false;

		__asm {
		sub esp, 14h
		lea eax, [isuniq]
		mov [esp+0Ch], eax
		mov [esp+08h], 0ffffffffh
		mov esi, uuidlist
		mov eax, [esi]
	/* Hack for release builds */
		test eax, 0F0h
		jz cu_uhhh
		mov eax, 2
	cu_uhhh:
		mov ecx, eax
		mov dword ptr [esp+04h], ecx
		add esi, 4
		mov [esp], esi
	/* Load from the back of the uuid array */
	lp1:
		lea edi, [esi+ecx*8]
		push edi
		sub [esp], esi
		pop eax
	/* If ECX==01 : ensure we stay aligned on last uuid */
		cmp ecx, 01h
		jne lp1_aa
		shl eax, 1
	lp1_aa:
		imul eax, ecx
		lea edi, [esi+eax*1]
		sub edi, 10h
	/* Break outta loop, lp1, here */
		test ecx, ecx
		jz lp1_dn
		mov edx, [edi]
		mov eax, 1
		and edx, [esp+08h]
		jnz lp1_2_1
		and dword ptr [isuniq], 0
		xor eax, eax
		jz lp1_2
lp1_2_1:
		mov dword ptr [isuniq], 1
lp1_2:
		xchg ecx, [esp+0Ch]
		test [ecx], 01h
		jz lp1_2a
		xor eax, eax
lp1_2a:
		xor [ecx], eax
		xchg ecx, [esp+0Ch]
		dec ecx
		cmp esi, edi
		jb lp1
lp1_dn:
		add esp, 10h
		}

		return isuniq;
}

		

extern "C" ATOM APIENTRY createPersistWindow(HINSTANCE hInst, uniqpers_idbox *uuidlist, unique_persist *upcls )
{
	size_t uuidlen = -1;
	bool notfirstinst = false;
	bool cuu_rv;
	WNDCLASSEX fakewc = {0};
	fakewc.cbSize = sizeof(WNDCLASSEX);

	long instances_of_app = 1; //todo


	cuu_rv = checkuuidunique(uuidlist);

	if (!cuu_rv)
	{
		RaiseException(EXCEPTION_FLT_INVALID_OPERATION, 0, 0, NULL);
		return 0xFFFF;
	}

	::unique_persist::setup_uuid_string(*upcls);

	const bool wegood = ::unique_persist::first_uuid_good(static_cast<unsigned short>(cuu_rv), &uuidlen);

	const long insts = ::g_balkin_instance;
	if (InterlockedCompareExchange(&::g_balkin_instance, insts, instances_of_app-1) == 0)
	{
		notfirstinst &= false;
	}
	else
	{
		instances_of_app += insts;
		notfirstinst = true;
	}

	if (!wegood)
	{
		if (uuidlen == -1)
		{
			RaiseException(EXCEPTION_FLT_INVALID_OPERATION, 0, 0, NULL);
			return 0xFFFF;
		}
		else if (uuidlen > 0)
		{
			try
			{
				std::fill<TCHAR*, TCHAR>(upcls->get_uidnam_ptr(), upcls->get_uidnam_ptr()+256, '\x00\x00');
			}
			catch (...)
			{
				::unique_persist::setup_uuid_string(*upcls);
			}

		}

		StringFromGUID2(uuidlist->uuid[1], upcls->get_uidnam_ptr(), 256);
	}
	else
	{
		StringFromGUID2(uuidlist->uuid[1], upcls->get_uidnam_ptr(), 256);
		
		if (notfirstinst)
		{
		}

	}	

	fakewc.hInstance = hInst;
	fakewc.style = CS_GLOBALCLASS;
	/* a guid genn'd earlier shall name this window class */
	fakewc.lpszClassName = upcls->get_uidnam_ptr();
	/* actual xtra's that will be used */
	fakewc.cbWndExtra = WNDCLASS_WINXTRAS*sizeof(long);
	/* clsExtra's are being abused. This field Be misused to count each process' own class per Inst like 
	 ** an index */
	(!notfirstinst) ? fakewc.cbClsExtra = 1-instances_of_app : fakewc.cbClsExtra = instances_of_app;

	return RegisterClassEx(&fakewc);

};
