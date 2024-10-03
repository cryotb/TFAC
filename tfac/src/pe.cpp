#include "inc/include.h"

namespace pe
{
    std::vector<pe_change> check_integrity(void *image, size_t image_len, const char *path)
    {
        auto result = std::vector<pe_change>();
        size_t dwdisk_image_len = 0;

        auto pdisk_image = (uint8_t *)tools::memmap_file(path, &dwdisk_image_len);
        if (pdisk_image)
        {
            auto phdr_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(pdisk_image);
            auto phdr_nt = reinterpret_cast<PIMAGE_NT_HEADERS>(BASE_OF(pdisk_image) + phdr_dos->e_lfanew);

            if (phdr_dos->e_magic == IMAGE_DOS_SIGNATURE &&
                phdr_nt->Signature == IMAGE_NT_SIGNATURE)
            {
                if (phdr_nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
                {
                    std::vector<uint8_t> vec_memory_image_snap(image_len);

                    if (!tools::memcpy_eh(vec_memory_image_snap.data(), image, vec_memory_image_snap.size()))
                        goto cleanup;

                    auto pmemory_image_snap = vec_memory_image_snap.data();
                    auto pmemory_image_end = BASE_OF(image) + image_len;

                    pe::reverse_relocations(pmemory_image_snap, BASE_OF(image), phdr_nt);

                    auto section_hdr = IMAGE_FIRST_SECTION(phdr_nt);
                    for (uint16_t i = 0; i < phdr_nt->FileHeader.NumberOfSections; i++)
                    {
                        auto psection = &section_hdr[i];
                        auto section_name = pe::secname_tostr(psection);

                        // skip noaccess
                        if (!(psection->Characteristics & IMAGE_SCN_MEM_READ))
                            continue;

                        // skip writable
                        if ((psection->Characteristics & IMAGE_SCN_MEM_WRITE) != 0)
                            continue;

                        if (section_name != ".text")
                            continue;

                        auto section_ptr_disk = reinterpret_cast<uint8_t *>(pdisk_image + psection->PointerToRawData);
                        auto section_ptr_mem = reinterpret_cast<uint8_t *>(pmemory_image_snap + psection->VirtualAddress);

                        auto diffs = tools::diff_binary_data(section_ptr_disk, section_ptr_mem, psection->SizeOfRawData);

                        if (!diffs.empty())
                        {
                            for (const auto &bdiff : diffs)
                            {
                                pe_change rec;
                                rec.section = section_name;
                                rec.rva = BASE_OF(psection->VirtualAddress) + bdiff.rva;
                                rec.len = bdiff.len;
                                result.push_back(rec);
                            }
                        }
                    }
                }
            }

        cleanup:
            UnmapViewOfFile(pdisk_image);
        }

        return result;
    }
}
