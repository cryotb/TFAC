set CLANG_EXE="clang++.exe"
%CLANG_EXE% --version
%CLANG_EXE% -m32 -shared src/*.cpp -o progi.dll -luser32 -fno-unwind-tables -std=c++20 -g -O0 -mllvm -csobf ^
-Wl,-nodefaultlib:libcmt -D_DLL -lmsvcrt -Wno-microsoft-cast -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH ^
-Wl,/FORCE:MULTIPLE
