#include <tchar.h>
#include <Windows.h>
#include "balkin.hpp"
#include "install.h"
#include "unique_persist.h"
#include "wndclass.h"

typedef balkin_startup_info ProcStartInfo;

int APIENTRY ourWinVersion(void)
{
	DWORD version = 0;
	OSVERSIONINFO osvi = {0};
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

	GetVersionEx(&osvi);

	version = osvi.dwMajorVersion;

	// Return a '7' for windows 7. :)
	(osvi.dwMajorVersion == 6) ? version += osvi.dwMinorVersion : 0;

	return version;
}

int APIENTRY doProcessInitialization(HINSTANCE hInstance, LPDWORD lpTlsIndex)
{
	ProcStartInfo  procInfo = {0};
	bool hasInfo = true;
	long proc_inst = 0;
	int extra_code = 0;

	procInfo.si.cb = sizeof(ProcStartInfo);

	/* Get our TLS index & set to allocated heap memory */
	*lpTlsIndex = TlsAlloc();
	TlsSetValue(g_tlsindex, HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4096));

	// //
	// TRY & GET STARTUPINFO
	try
	{
		GetStartupInfo(reinterpret_cast<LPSTARTUPINFO>(&procInfo));
	}
	catch (...)
	{
		hasInfo &= false;
	}
					
	if ((DWORD) procInfo.si.hStdOutput != BSI_VERIFY_CONST)
	{
		hasInfo &= false;
	}
	//
	// true  = we child process
	// false = we the parent process
	if (hasInfo)
	{
		(procInfo.si.cbReserved2 > 0) ? proc_inst = procInfo.si.cbReserved2 : 0;
		InterlockedExchangeAdd(&::g_balkin_instance, proc_inst);
		InterlockedIncrement(&::g_balkin_instance);

		extra_code |= 100;
	}

	if (!is_installed_image(hInstance))
	{
		extra_code |= 200;
	}

	return 0 + extra_code;
}


int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);

	/* balkin's persistence module. unfriendly guid identz & etc-rel found within */
	unique_persist		persistence;
	/* 888888888 */ LPVOID  upc_offset;  // offset in the guid array
	/* 888888888 */ size_t  upc_pastdat; // numerical vers of above.

	/* balkin's installer module. */
	balkinstaller		installer(ourWinVersion());

	/* GET INFORMATION ABOUT OUR PROCESS ASAP!! */
	const int process_info = doProcessInitialization(hInstance, &g_tlsindex);
	int       proc_state;
	/***
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * *
	 * CONTROL FLOW FROM HERE BASED ON INFORMATION THAT CAN BE GATHERED ABOUT AN INSTANCE
	 * * FORKED / SPAWNED CHILD PROCESSES WILL HAVE THEIR BEHAVIOR DET'D HERE
	 * INSTALLATION & RELATED TASKS ARE CONTROL'D HERE AS WELL...
	 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *  * * * * * * * * * * *
	***/
	(process_info != 0) ? proc_state = process_info / 100 : proc_state = process_info;
	switch (proc_state)
	{
	/* p_S = 0: NORML LAUNCH */
		case 0:

			// non-spawned / original instance'z always make fresh new persist info
			persistence.populate_guids(UPM_CREATENEW);
			::unique_persist::make_inheritable_pipes(persistence);

			/* remove any seq's of zeros in the second GUID */
			upc_pastdat = persistence.guid_fillcnt(&upc_offset);
			persistence.gen_unique_uuid(2, upc_pastdat, upc_offset);
		break;
	/* p_S = 100: CHILD PROCESS */
		case 1:
			// bleh
		break;
	/* p_S = 200: NOT INSTALLED */
		case 2:

			// non-spawned / original instance'z always make fresh new persist info
			persistence.populate_guids(UPM_CREATENEW);
			::unique_persist::make_inheritable_pipes(persistence);

			/* remove any seq's of zeros in the second GUID */
			upc_pastdat = persistence.guid_fillcnt(&upc_offset);
			persistence.gen_unique_uuid(2, upc_pastdat, upc_offset);

			/* get persistence shit for the installer & do the install */
			installer.obtain_identifiers(persistence);
			installer.do_installation();
		break;
	/* p_S = 300: CHILD PROCESS | NOT INSTALLED */
		case 3:
			//bleh
		break;
		default:
			//bleh
		break;
	}

	/*

	persistence.populate_guids(UPM_READEXISTING);

	size_t s = persistence.guid_fillcnt(&lel);

	persistence.gen_unique_uuid(2, s, lel);
	*/
	unique_persist		*p2 = new unique_persist(persistence);

	createPersistWindow(hInstance, &persistence.hash_guids, &persistence);

	delete p2;

	HeapFree(GetProcessHeap(), 0, TlsGetValue(g_tlsindex));
	TlsFree(g_tlsindex);

	return 0;
}
