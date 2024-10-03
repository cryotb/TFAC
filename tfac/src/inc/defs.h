#pragma once

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

#define BASE_OF(X) ((DWORD_PTR)X)
#define POINTER_OF(X) ((PVOID)X)
