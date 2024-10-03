#pragma once

#include <cstdint>
#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <thread>

#if !defined(WIN32_LEAN_AND_MEAN)
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <wincrypt.h>
#include <WinTrust.h>
#include <mscat.h>
#include <TlHelp32.h>
#include <Softpub.h>
#endif

#pragma comment(lib, "crypt32.lib")
#pragma comment (lib, "AdvApi32.lib")

#include "defs.h"
#include "pe.h"
#include "tools.h"
#include "log.h"

#include "tfac.h"

extern Tfac* ginst;
