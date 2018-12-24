#include <cstdint>
#include <memory>
#include "unique_persist.h"
#include <Windows.h>
#include <WinCrypt.h>

TCHAR *unique_persist::sp_uuidname = NULL;
bool unique_persist::sp_uidnamgood = false;

unique_persist::unique_persist(const unique_persist& other) :
	p_piperaw(NULL)
{
	DWORD dwjunk = 0;
	HANDLE hProc = GetCurrentProcess();
	std::pair<uuidcontainer<2>*,int> mem = std::get_temporary_buffer<uuidcontainer<2>>(1);

	std::uninitialized_copy_n(&other.hash_guids, mem.second, mem.first);
	std::swap<uuidcontainer<2>>(*mem.first, this->hash_guids);
	std::return_temporary_buffer<uuidcontainer<2>>(mem.first);

	if (other.p_piperaw != NULL)
	{
		this->p_piperaw = new BYTE[UPM_PIPERAW_SIZE];
		memcpy((void*)this->p_piperaw, (void*)other.p_piperaw, UPM_PIPERAW_SIZE);
	}

	p_pipepresent = other.p_pipepresent;
	p_pipename	  = g_pipename;

	if (GetHandleInformation(other.p_npipe, &dwjunk) != 0)
			DuplicateHandle(hProc, other.p_npipe, hProc, &this->p_npipe, DUPLICATE_SAME_ACCESS,
							TRUE, 0);
	if (GetHandleInformation(other.p_npcl, &dwjunk) != 0)
			DuplicateHandle(hProc, other.p_npcl, hProc, &this->p_npcl, DUPLICATE_SAME_ACCESS,
							TRUE, 0);

	p_crypto	  = other.p_crypto;
	p_uuidstring  = other.p_uuidstring;
}

unique_persist::~unique_persist()
{
	if (p_piperaw != NULL)
		delete[] p_piperaw;

	if (p_crypto != NULL)
		CryptReleaseContext(p_crypto, 0);

	if (p_npipe)
	{
		DisconnectNamedPipe(p_npipe);
		CloseHandle(p_npipe);
	}

	if (p_npcl)
		CloseHandle(p_npcl);

}

bool unique_persist::checkforpipe()
{
	DWORD	lpBytesRead = 0;
	bool	test1 = false;
	bool	test2 = false;

	if (p_pipepresent != false)
	{
		return p_pipepresent;
	}

	if (p_npcl != NULL)
	{
		test2 = true;
	}

	if (p_npipe != NULL)
	{
		if (GetNamedPipeInfo(p_npipe, NULL, NULL, NULL, NULL))
			test1 = true;

		if (!test2 && test1)
		{
			p_pipepresent = true;
		}
		else
		{
			p_pipepresent = test1 & test2;
		}
	}

	return p_pipepresent;
}

int unique_persist::populate_guids(const int mode)
{
	int retval	= 0;
	BOOL bChk = 0;
	DWORD bytesreadorwrite = 0;
	DWORD bytesavail, bytesleft;
	DWORD bytesreadfil = 0;
	intptr_t readptr = 0;
	intptr_t modulptr = 0;
	HCRYPTHASH	pChash = 0;
	LPBYTE lpShaRaw = new BYTE[2*20+8];

	UUID	uuidtemp = {0};

	OVERLAPPED olap = {0};

	memset(lpShaRaw, '\0', 2*20+8);

	if (!this->checkforpipe() || p_npipe == NULL)
	{
		p_npipe = CreateNamedPipe(p_pipename,
						PIPE_ACCESS_DUPLEX,
						PIPE_TYPE_BYTE  | PIPE_READMODE_BYTE,
						254,
						2 << 11, 2 << 11, 0, NULL);

		if (p_npipe == INVALID_HANDLE_VALUE)
		{
			delete[] lpShaRaw;
			return -1;
		}

		// Change return value if the pipe's current status differs from
		//  what would be expected of it based on the chosen mode 
		switch (mode)
		{
		case UPM_READEXISTING:
			(!p_pipepresent) ? retval = UPM_PGMODE_DIFF : 0;
			if (retval != 0) { goto PG_createnew; } else { goto PG_readexist; }
			break;
		case UPM_CREATENEW:
			(p_pipepresent) ? retval = UPM_PGMODE_DIFF : 0;
			goto PG_createnew;
			break;
		default:
			break;
		}
	}

	switch (mode)
	{
	case UPM_READEXISTING:
			goto PG_readexist;
		break;
	case UPM_CREATENEW:
			goto PG_createnew;
		break;
	default:
		break;
	}

PG_readexist:
	if (p_piperaw == NULL)
	{
		p_piperaw = new BYTE[UPM_PIPERAW_SIZE];
		memset(p_piperaw, '\0', UPM_PIPERAW_SIZE);
		/* allocate enough space for two SHA1 hashes with a sep. byte and 4B of xtra*/
	}
	else
	{
		memset(p_piperaw, '\0', UPM_PIPERAW_SIZE);
	}

	bChk = PeekNamedPipe(p_npipe, p_piperaw, UPM_PIPERAW_SIZE, &bytesreadfil, &bytesavail, &bytesleft);
	
	/* * A SHA1 hash's length of data or more was found, 20B/160b * */
	if (bChk == TRUE && bytesreadfil >= 20)
	{
		for (int i=0; i < 2; i++)
		{
			readptr = (intptr_t) p_piperaw;
			readptr += i*sizeof(UUID);
			memmove((void*)&uuidtemp, (void*)readptr, sizeof(UUID));
			memcpy((void*)&hash_guids.uuid[i], (void*)&uuidtemp, sizeof(UUID));
		}

		return retval;
	}
	else
	{
		if (this->checkforpipe())
			goto PG_createnew;

		return -1;
	}

	if (lpShaRaw)
		delete[] lpShaRaw;

	return retval;

PG_createnew:
	if (p_crypto == NULL)
	{
		bChk = CryptAcquireContext(&p_crypto, NULL, NULL,
					PROV_RSA_FULL,
					CRYPT_SILENT);

		if (!bChk)
		{
			delete[] lpShaRaw;
			return -1;
		}
	}
	
	bChk = CryptCreateHash(p_crypto, CALG_SHA1, 0, 0, &pChash);

	if (!bChk)
	{
		delete[] lpShaRaw;
		return -1;
	}

	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER) GetModuleHandle(NULL);
	modulptr = (intptr_t) pDosHdr;
	modulptr += pDosHdr->e_lfanew;
	modulptr += sizeof(DWORD)+sizeof(IMAGE_FILE_HEADER);
	PIMAGE_OPTIONAL_HEADER pOptHdr = (PIMAGE_OPTIONAL_HEADER) modulptr;
	
	bChk = CryptHashData(pChash, (const BYTE*)GetModuleHandle(NULL), pOptHdr->SizeOfImage, 0);

	if (!bChk)
	{
		delete[] lpShaRaw;
		return -1;
	}

	bytesreadorwrite = 2*20+8;
	bChk = CryptGetHashParam(pChash, HP_HASHVAL, lpShaRaw, &bytesreadorwrite, 0);


	if (bChk)
	{
		for (int j=0; j < 2; j++)
		{
			readptr = (intptr_t) lpShaRaw;
			readptr += j*sizeof(UUID);
			memmove((void*)&uuidtemp, (void*)readptr, sizeof(UUID));
			memcpy((void*)&hash_guids.uuid[j], (void*)&uuidtemp, sizeof(UUID));
		}
	}
	else
	{
		delete[] lpShaRaw;
		return -1;
	}

	CryptDestroyHash(pChash);

	if (p_npcl == NULL)
	{
		p_npcl = CreateFile(p_pipename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (p_npcl == INVALID_HANDLE_VALUE)
			return -1;
	}

	bChk = WriteFile(p_npcl, (LPCVOID)lpShaRaw, 1+2*sizeof(UUID), &bytesreadorwrite, NULL);

	delete[] lpShaRaw;

	if (!bChk)
		return -1;

	return retval;
}

bool unique_persist::gen_unique_uuid(const int hindex, size_t unibytes, void *offset)
{
	size_t allocmuch = unibytes;
	size_t limit	 = unibytes;
	size_t borword	 = 0;
	const unsigned short andme[2] = {0xFF00L, 0x00FFL};
	unsigned short word = 0;
	unsigned short *testpt = NULL;
	int				incr = 0;
	LPBYTE uniquedat = new BYTE[unibytes+1];
	LPBYTE uniquedat2 = uniquedat;
	LPVOID heapptr   = NULL;
	intptr_t heapadd = 0;

	(allocmuch % 2 == 0) ? allocmuch *= 8 : allocmuch = 1+allocmuch*8;
	heapptr = HeapAlloc(GetProcessHeap(), NULL, allocmuch);
	heapadd = (intptr_t ) heapptr;

	for (unsigned int i=0; i < allocmuch; i += sizeof(unsigned short))
	{
		(incr != 0 && incr < 2) ? (i > 2) ? uniquedat = uniquedat2 + i : uniquedat = uniquedat2 + 1 : uniquedat = uniquedat2 + i;

		if (limit == 0)
			break;

		heapadd += i;
		testpt = (unsigned short*)heapadd;
		word = *testpt & andme[0];
		word = word >> 8;

		if ((*testpt & 256) >= 256)
		{
			incr = 2;
			memmove((void*)uniquedat, (void*)heapadd,sizeof(unsigned short));
			limit -= sizeof(unsigned short);
			continue;
		}
		if (word > 0)
		{
			(word > 255) ? borword = sizeof(unsigned short) : borword = sizeof(unsigned char);
			(word > 255) ? incr = 2 : incr = 1;
			memmove((void*)uniquedat, (void*)heapadd, borword);
			limit -= borword;
		}
		else
		{
			word = *testpt & andme[1];
					if (word > 0)
					{
						(word > 255) ? borword = sizeof(unsigned short) : borword = sizeof(unsigned char);
						(word > 255) ? incr = 2 : incr = 1;
						memmove((void*)uniquedat, (void*)heapadd, borword);
						limit -= borword;
					}
		}
	}

	if (&hash_guids.uuid[hindex-1].Data2 != offset)
	{
		if (offset != NULL)
		{
			memcpy(offset, (void*)uniquedat2, unibytes);
		}
		else
		{
			memcpy((void*)&hash_guids.uuid[hindex-1].Data2, (void*)uniquedat2, unibytes);
		}
	}
	else
	{	memcpy(offset, (void*)uniquedat2, unibytes); }
	/* } */

	HeapFree(GetProcessHeap(), 0, heapptr);

	UUID	genneduuid = {0};

	UuidCreateSequential(&genneduuid);
	
	unsigned int randum1 = genneduuid.Data2 | genneduuid.Data3 << 16;
	unsigned int randum2 = reinterpret_cast<unsigned int>(genneduuid.Data4);
	unsigned int randum3 = genneduuid.Data1;
	
	void *voffset = offset; // inline asm cannot have var be name'd this

	/* Make the unique part of the second uuid, well, more unique		 *
	 *  Uses MMX to XOR the data past the Data1 field in the second uuid *
	 *				*					*					*			 */
	__asm {
		sub esp, 14h
		lea edx, [esp]
		mov eax, unibytes
		mov [esp+16], eax
		mov ecx, voffset
		mov [edx], ecx
		sub eax, 8
		pxor mm0, mm0
		movq mm1, mm0
		movq mm2, mm0
		movd mm0, [ecx]
		psllq mm0, 20h
		movd mm1, [ecx+4]
		por mm0, mm1
		lea esi, [ecx+8]
		lodsd
		movd mm2, eax
		movd mm1, randum1
		pxor mm0, mm1
		movd mm1, randum2
		pxor mm2, mm1
		pxor mm1, mm1
		movq mm3, mm0
		movd mm4, randum3
		psllq mm4, 20h
		por mm0, mm4
		lea edi, [esp+04h]
		punpckhdq mm0, mm1
		movd [edi], mm0
		movd [edi+4], mm3
		movd [edi+8], mm2
		mov esi, [edx]
		xchg edi, esi
		mov ecx, [esp+16]
		shr ecx, 02h
		rep movsd
		add esp, 14h
		emms
	}

	return true;
}


size_t unique_persist::guid_fillcnt(void **fillat)
{
	LPVOID lpSecondUuid = &hash_guids.uuid[1];
	intptr_t offset = (intptr_t) lpSecondUuid;
	intptr_t offset2 = offset + sizeof(UUID);
	unsigned char nb = '\x00';
	LPVOID lpFillstart = NULL;
	size_t fillablebytes = 0;

	while (offset < offset2)
	{
		if(memcmp(reinterpret_cast<void*>(offset), (void*)&nb, 1) == 0)
		{
			fillablebytes++;
		}
		if (fillablebytes == 1)
		{
			lpFillstart = (LPVOID)offset;
		}
		offset++;
	}

	*fillat = lpFillstart;

	return fillablebytes;
}

bool unique_persist::first_uuid_good(const unsigned short skipfaltru, size_t *uns_len)
{
	void **vptr = (void**)&unique_persist::sp_uuidname;
	
	if (skipfaltru >= 0)
	{
		sp_uidnamgood = true;

		if (skipfaltru == 0)
			sp_uidnamgood = sp_uidnamgood & false;
	}

	if (sp_uuidname != NULL)
	{
		size_t uidnamlength = _tcscnlen(::unique_persist::sp_uuidname, 256);
		size_t maxlens[2] = { 39, 40 };

		if (!sp_uidnamgood)
		{
			(uidnamlength > 0) ? *uns_len = uidnamlength : *uns_len = 0;
			return sp_uidnamgood;
		}

		switch (uidnamlength)
		{
			case 0:
				sp_uidnamgood = false;
				*uns_len = uidnamlength;
			break;
			case 39:
				sp_uidnamgood = true;
				*uns_len = uidnamlength;
			break;
			case 40:
				sp_uidnamgood = true;
				*uns_len = uidnamlength;
			break;
			default:
				if (uidnamlength >= maxlens[0] || uidnamlength >= maxlens[1])
				{
					sp_uidnamgood = true;
				}
				else
				{
					sp_uidnamgood = false;
				}
				*uns_len = uidnamlength;
			break;
		}

		return sp_uidnamgood;
	}
	else
	{
		sp_uuidname = NULL;
		sp_uidnamgood = false;
		*uns_len = -1;
	}

	return sp_uidnamgood;
}

void unique_persist::setup_uuid_string(unique_persist& cls)
{
	if (cls.p_uuidstring == NULL || sp_uuidname == NULL)
	{
		if (sp_uuidname && !cls.p_uuidstring) {
			cls.p_uuidstring = &unique_persist::sp_uuidname;
			return;
		}
		sp_uuidname = new TCHAR[256];
		std::fill<TCHAR*, TCHAR>(sp_uuidname, sp_uuidname+256, '\x00\x00');
		cls.p_uuidstring = &unique_persist::sp_uuidname;
	}
	
	return;
}

void unique_persist::make_inheritable_pipes(unique_persist& cls)
{
	HANDLE hands[2] = {cls.p_npipe, cls.p_npcl };

	for (int i=0; i < 2; i++)
	{
		if (hands[i] == NULL)
			continue;

		SetHandleInformation(hands[i], HANDLE_FLAG_INHERIT, 0);
	}

	return;
}
