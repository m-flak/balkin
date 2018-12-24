#pragma once

#include <cstdlib>
#include <Rpc.h>
#include <iterator>
#include <assert.h>

template <int I>
struct uuidcontainer
{

	unsigned long count;
	UUID		  uuid[I];

	uuidcontainer()
		: count(I)
	{
		memset(&uuid, '\0', I*sizeof(UUID));
	}

};

template <int I, typename data>
static size_t uuidcontainer_size()
{
	const size_t uuids = sizeof(data)*I;
	const size_t cntsz = sizeof(unsigned long);
	return uuids + cntsz;
}

typedef uuidcontainer<2> uniqpers_idbox;
