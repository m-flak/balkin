#pragma once

#include <Windows.h>
#include <cstdtchar>
#include "unique_persist.h"


static TCHAR* g_dnsfolder = _T("Documents and Settings"); 
static TCHAR* g_usrfolder = _T("Users");
static TCHAR* g_userprofile = _T("USERPROFILE");
static TCHAR* g_username = _T("USERNAME");


/* ''Installed'' executable will have its e_maxalloc sub'd by 1 when it is copied
 *		to where it needs to be.
 *	If the current process was not executed from this modified exe, then when we
 *		assume there is work to do.
 *
 */
extern "C" bool __stdcall is_installed_image(HINSTANCE hInst);

class balkinstaller
{
public:
	balkinstaller(const int winVer);
	virtual ~balkinstaller();

	virtual long do_installation();

	void obtain_identifiers(const unique_persist& pers);

protected:
	virtual bool gethome_one();
	
	virtual bool gethome_two();

	virtual bool getdata_one();

private:
	long p_winver;

	TCHAR *p_homedir;
	TCHAR *p_myident;
public:
	std::tstring user_name;
	std::tstring install_path;
	std::tstring users_folders;
};
