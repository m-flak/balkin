#pragma once

#include <Windows.h>
#include <Rpc.h>
#include "uuidcontainer.h"
#include "unique_persist.h"

#define WNDCLASS_WINXTRAS 2

extern "C" ATOM APIENTRY createPersistWindow(HINSTANCE hInst, uniqpers_idbox *uuidlist, unique_persist *upcls );
