#include "inc/include.h"

Tfac *ginst = nullptr;

void Tfac::start()
{
    tools::create_console();

    compose_modules();

    /* perform our initial analysis. */
    printf("------( SIGNED modules )------\n");
    for (const auto &mod : _signed_modules)
    {
        printf(" - %s\n", mod.name.c_str());
    }
    printf("------------------------------\n");

    printf("------( UNSIGNED modules )------\n");
    for (const auto &mod : _unsigned_modules)
    {
        printf(" - %s\n", mod.name.c_str());
    }
    printf("------------------------------\n");
    /*  */

    std::thread(&Tfac::thread, this).detach();

    printf("started!\n");
}

void Tfac::thread()
{
    do
    {
        tick();
        Sleep(5000);
    } while (true);
}

void Tfac::tick()
{
    AcquireSRWLockExclusive(&_lock);

    compose_modules();
    compose_valve_ifaces();

    analyze_valve_ifaces();
    analyze_readonly_integrity();

    ReleaseSRWLockExclusive(&_lock);
}

void Tfac::compose_modules()
{
    _signed_modules.clear();
    _unsigned_modules.clear();

    auto mods = tools::get_process_modules(GetCurrentProcess());
    for (const auto &mod : mods)
    {
        if (mod.base == (uintptr_t)&__ImageBase)
        {
            _self = mod;
            continue;
        }

        auto cinf = tools::get_cert_info(mod.path.c_str());
        if (cinf.lookup_status == tools::cert_lookup_states::OK)
        {
            _signed_modules.push_back(mod);
        }
        else
        {
            _unsigned_modules.push_back(mod);
        }
    }
}

void Tfac::compose_valve_ifaces()
{
    _valve_ifaces.clear();

    typedef void *(*create_iface_fn)(const char *, int *);
    for (const auto &mod : _signed_modules)
    {
        struct valve_iface_record_t
        {
            void *(*getter)();
            const char *name;
            valve_iface_record_t *next;
        };

        if (mod.name == "steamclient.dll" || mod.name == "vstdlib_s.dll" || mod.name == "crashhandler.dll")
            continue;

        auto pfn_create_iface_wrapper = (create_iface_fn)GetProcAddress((HMODULE)mod.base, "CreateInterface");
        if (pfn_create_iface_wrapper != nullptr)
        {
            auto insn_addr_jmp = reinterpret_cast<uintptr_t>(pfn_create_iface_wrapper) + 4;
            auto fun_addr_create_iface = insn_addr_jmp + *(uint32_t *)(insn_addr_jmp + 0x1) + 0x5;

            auto iface_list = **reinterpret_cast<valve_iface_record_t ***>(fun_addr_create_iface + 0x4 + 0x2);
            auto iface = iface_list;
            if (iface != nullptr)
            {
                do
                {
                    auto pbase = iface->getter();
                    if (pbase)
                    {
                        valve_interface_t rec;
                        rec.mod = mod;
                        rec.name = iface->name;
                        rec.base = (uintptr_t)pbase;
                        _valve_ifaces.push_back(rec);
                    }

                    iface = iface->next;
                } while (iface != nullptr);
            }
        }
    }
}

void Tfac::analyze_valve_ifaces()
{
    printf("------( VALVE IFACES )------\n");

    for (const auto &iface : _valve_ifaces)
    {
        auto vftable = *(void ***)iface.base;
        auto vftable_base = (uintptr_t)vftable;

        /* an object can have multiple vftables, however we only check first one for now. */
        /* todo: add checks for obj+4, +8, etc maybe. */

        if (IsBadReadPtr(vftable, sizeof(uintptr_t)))
            continue;

        bool backed = false;

        for (const auto &mod : _signed_modules)
        {
            if (vftable_base >= mod.base && vftable_base < (mod.base + mod.size))
            {
                backed = true;
                break;
            }
        }

        if (!backed)
        {
            log::flag("compromised virtual method table on IFACE %s => %p",
                   iface.name.c_str(), vftable);

            backtrack_hooked_vftable(iface.name.c_str(), vftable);
        }
    }

    printf("-----------------------\n");
}

void Tfac::backtrack_hooked_vftable(const char *iface_name, void **vftable)
{
    size_t count = tools::vft_calc_count((uintptr_t *)vftable);
    if (count < 1)
    {
        printf("[ERROR] vftable cannot be empty -> %p\n", vftable);
        return;
    }

    for (size_t i = 0; i < count; i++)
    {
        auto handler = (uintptr_t)vftable[i];

        bool backed = false;

        for (const auto &mod : _signed_modules)
        {
            if (handler >= mod.base && handler < (mod.base + mod.size))
            {
                backed = true;
                break;
            }
        }

        if (!backed)
        {
            log::flag("  %p hooked handler -> %i @ %p", vftable, i, handler);

            MEMORY_BASIC_INFORMATION mbi;
            memset(&mbi, 0, sizeof(mbi));

            if (VirtualQuery(POINTER_OF(handler), &mbi, sizeof(mbi)) > 0)
            {
                if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)
                {
                    log::flag("-> %p | %i handler page is executable (1).", vftable, i);

                    if (mbi.Type != MEM_IMAGE)
                    {
                        log::flag("-> %p | %i handler page is manually allocated (2).", vftable, i);
                        /* owned */
                    }
                }
            }
        }
    }
}

uint32_t resolve_jump_dst(const uint8_t *data)
{
    switch (data[0])
    {
    case 0xE9:
    {
        int32_t disp32 = *(int32_t *)(data + 1);
        return (uint32_t)(data + 5 + disp32);
    }
    default:
        return 0;
    }
}

void Tfac::analyze_readonly_integrity()
{
    for (const auto &mod : _signed_modules)
    {
        if(mod.name != "client.dll" && mod.name != "engine.dll")
            continue;

        auto diffs = pe::check_integrity((void *)mod.base, mod.size, mod.path.c_str());
        if (diffs.size() > 0)
        {
            printf("----------------------------------------------\n");
            printf(" [*] found %d diffs in %s.\n", diffs.size(), mod.name.c_str());

            for (const auto &diff : diffs)
            {
                auto patch = reinterpret_cast<uint8_t*>(mod.base + diff.rva);

                /*printf("   [%s][%x] L%x (%p)\n",
                       diff.section.c_str(), diff.rva, diff.len, patch);

                printf("bytes:\n");
                for(uint32_t i = 0; i < diff.len; i++)
                {
                    printf("%02X ", patch[i]);
                }
                printf("\n");*/

                auto jump_dst = resolve_jump_dst(patch);
                if(jump_dst != 0)
                {
                    /* patch is a JUMP supported by our disasm. */
                    if(!is_backed_by_signed_module(jump_dst))
                    {
                        log::flag("[CFR] unsigned jump located at %p, going to %p.", patch, jump_dst);
                        
                        /* some sanity checks to verify */
                        MEMORY_BASIC_INFORMATION mbi;
                        memset(&mbi, 0, sizeof(mbi));

                        if(VirtualQuery(POINTER_OF(jump_dst), &mbi, sizeof(mbi)) > 0)
                        {
                            if(mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)
                            {
                                log::flag("  -> %p | %p destination page is executable (1).", patch, jump_dst);

                                if(mbi.Type != MEM_IMAGE)
                                {
                                    log::flag("  -> %p | %p destination page is manually allocated (2).", patch, jump_dst);
                                    /* owned */
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
