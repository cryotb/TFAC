#pragma once

struct valve_interface_t
{
    tools::module_t mod;
    std::string name;
    uintptr_t base;
};

class Tfac
{
public:
    void start();

    void thread();
    void tick();

    /* composes two lists, one containing signed and the other unsigned modules in the current process. 
     * make sure to call this anytime you're performing checks and analyses depending on these lists! */
    void compose_modules();

    /* composes a list of all valve interfaces. */
    void compose_valve_ifaces();

    /* verify integrity of all valve interfaces. */
    void analyze_valve_ifaces();

    /* verify integrity of read only sections. */
    void analyze_readonly_integrity();

    /* this can be used to enumerate vftable handlers if suspected. */
    void backtrack_hooked_vftable(const char* iface_name, void** vftable);

    bool is_backed_by_signed_module(uintptr_t addr)
    {
        for(const auto& mod : _signed_modules)
        {
            if(addr >= mod.base && addr < (mod.base + mod.size))
                return true;
        }

        return false;
    }
private:
    SRWLOCK _lock;
    tools::module_t _self;
    tools::module_list _signed_modules;
    tools::module_list _unsigned_modules;
    std::vector<valve_interface_t> _valve_ifaces;
};
