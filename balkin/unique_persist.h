#pragma once

#include <tchar.h>
#include <Windows.h>
#include <WinCrypt.h>
#include "uuidcontainer.h"

// MODE CONSTANTS for populate_guids
#define UPM_READEXISTING 1
#define UPM_CREATENEW	 2

// ALT. RETURN VALUE FOR populate_guids
#define UPM_PGMODE_DIFF  1000			/* The named pipe either existed/nonexisted *
										 *  contrary to the desired, chosen mode    */

#define UPM_PIPERAW_SIZE 4+2*21

typedef HANDLE up_pipe;
typedef HANDLE up_clipipe;

static TCHAR *g_pipename = _T("\\\\.\\pipe\\costanza");

class unique_persist
{

public:
		unique_persist() : p_pipepresent(false), p_pipename(g_pipename),
			p_npipe(NULL), p_piperaw(NULL), p_crypto(NULL), p_npcl(NULL),
			p_uuidstring(NULL)
			{}
		unique_persist(const unique_persist& other);
		virtual ~unique_persist();

		uuidcontainer<2> hash_guids;

		bool checkforpipe();

		int populate_guids(const int mode);

		// hindex should be 2 -- for the second uuid in hash_guids
		bool gen_unique_uuid(const int hindex, size_t unibytes, void *offset);

		size_t guid_fillcnt(void **fillat);

		static bool first_uuid_good(const unsigned short skipfaltru, size_t *uns_len);

		static void setup_uuid_string(unique_persist& cls);

		static void make_inheritable_pipes(unique_persist& cls);


		inline TCHAR* get_uidnam_ptr() { return *p_uuidstring; }

private:
		bool   p_pipepresent;
		TCHAR  *p_pipename;
		LPBYTE p_piperaw;

		TCHAR **p_uuidstring;

		up_pipe p_npipe;
		up_clipipe p_npcl;

		HCRYPTPROV p_crypto;

		static TCHAR *sp_uuidname;
		static bool sp_uidnamgood;

};
