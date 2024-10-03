#pragma once

namespace pe
{
	struct pe_change
	{
		pe_change()
		{
			section = "";
			rva = 0;
			len = 0;
		}

		std::string section;
		uint32_t rva;
		uint32_t len;
	};

	inline auto secname_tostr(PIMAGE_SECTION_HEADER psec)
	{
		char secname[9];
		memset(secname, 0, sizeof(secname));
		memcpy(secname, psec->Name, 8);
		return std::string(secname);
	}

	inline auto find_section(void *image, PIMAGE_NT_HEADERS nh, const char *name) -> PIMAGE_SECTION_HEADER
	{
		auto shdr = IMAGE_FIRST_SECTION(nh);

		for (uint16_t i = 0; i < nh->FileHeader.NumberOfSections; i++)
		{
			auto psec = &shdr[i];

			char secname[9];
			memset(secname, 0, sizeof(secname));
			memcpy(secname, psec->Name, 8);

			printf("%s\n", secname);

			if (strcmp(secname, name) == 0)
			{
				return psec;
			}
		}

		return nullptr;
	}

	struct reloc_t
	{
		uint16_t type;
		uint32_t rva;
	};

	inline auto get_relocs(void *image, PIMAGE_NT_HEADERS nh)
	{
		auto rs = std::vector<reloc_t>();

		auto reloc_dir = nh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (reloc_dir.Size > 0 && reloc_dir.VirtualAddress != 0)
		{
			auto base_reloc_start = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE *>(image) + reloc_dir.VirtualAddress);
			auto base_reloc_end = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE *>(base_reloc_start) + reloc_dir.Size);

			auto pbase_reloc = base_reloc_start;
			while (pbase_reloc < base_reloc_end && pbase_reloc->VirtualAddress && pbase_reloc->SizeOfBlock > 0)
			{
				auto num_entries = (pbase_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto reloc_data = reinterpret_cast<WORD *>(reinterpret_cast<BYTE *>(pbase_reloc) + sizeof(IMAGE_BASE_RELOCATION));

				for (auto i = 0ul; i < num_entries; ++i)
				{
					WORD reloc_entry = reloc_data[i];
					WORD reloc_type = reloc_entry >> 12;
					WORD reloc_offset = reloc_entry & 0xFFF;

					if (reloc_type == IMAGE_REL_BASED_HIGHLOW)
					{
						reloc_t rec;
						rec.type = reloc_type;
						rec.rva = pbase_reloc->VirtualAddress + reloc_offset;
						rs.push_back(rec);
					}
				}

				pbase_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE *>(pbase_reloc) + pbase_reloc->SizeOfBlock);
			}
		}

		return rs;
	}

	inline void reverse_relocations(void *remote_image_snap, uintptr_t remote_base, PIMAGE_NT_HEADERS nh)
	{
		auto adjust = remote_base - nh->OptionalHeader.ImageBase;

		for (const auto &rel : pe::get_relocs(remote_image_snap, nh))
		{
			if (rel.type == IMAGE_REL_BASED_HIGHLOW)
			{
				auto patch_addr = (void *)(BASE_OF(remote_image_snap) + rel.rva);
				*reinterpret_cast<DWORD *>(patch_addr) -= adjust;
			}
			else
			{
				printf("  [relcs] unknown type: %i", rel.type);
			}
		}
	}

	std::vector<pe_change> check_integrity(void *image, size_t image_len, const char *path);
}
