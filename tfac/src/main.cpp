#include "inc/include.h"

void ThMain(void* param)
{
    ginst = new Tfac();
    ginst->start();
}

unsigned long __stdcall DllMain(void* inst, unsigned long reason, void* reserved)
{
    if(reason == DLL_PROCESS_ATTACH)
    {
       std::thread(ThMain, inst).detach();
    }

    return 1;
}
