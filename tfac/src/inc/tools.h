#pragma once

namespace tools
{
    bool memcpy_eh(void *dst, const void *src, size_t len);

    inline unsigned int mmh32(const void *key, int len, unsigned int seed)
    {
        const unsigned int m = 0x5bd1e995;
        const int r = 24;

        unsigned int h = seed ^ len;

        const unsigned char *data = (const unsigned char *)key;

        while (len >= 4)
        {
            unsigned int k = *(unsigned int *)data;

            k *= m;
            k ^= k >> r;
            k *= m;

            h *= m;
            h ^= k;

            data += 4;
            len -= 4;
        }

        switch (len)
        {
        case 3:
            h ^= data[2] << 16;
        case 2:
            h ^= data[1] << 8;
        case 1:
            h ^= data[0];
            h *= m;
        };

        h ^= h >> 13;
        h *= m;
        h ^= h >> 15;

        return h;
    }

    inline double curtime()
    {
        static auto start = std::chrono::high_resolution_clock::now();
        auto now = std::chrono::high_resolution_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(now - start);
        return elapsed.count() / 1000000.0;
    }

    inline bool create_console()
    {
        auto result = AllocConsole();

        if (result == false && !(GetConsoleWindow() == nullptr))
            result = true;

        freopen_s(reinterpret_cast<FILE **>(stdin), "CONIN$", "r", stdin);
        freopen_s(reinterpret_cast<FILE **>(stdout), "CONOUT$", "w", stdout);

        return result;
    }

    inline bool file_exists(const std::string &path)
    {
        DWORD dwAttrib = GetFileAttributesA(path.c_str());

        return (dwAttrib != INVALID_FILE_ATTRIBUTES);
    }

    inline auto text_to_lower(const std::string &input)
    {
        auto output = std::string(input);

        std::transform(output.begin(), output.end(), output.begin(),
                       [](const unsigned char c)
                       { return std::tolower(c); });

        return output;
    }

    inline wchar_t *ustr2nulledws(PUNICODE_STRING str)
    {
        auto result = (wchar_t *)malloc(str->Length + sizeof(wchar_t));
        if (result)
        {
            memset(result, 0, str->Length + sizeof(wchar_t));
            memcpy(result, str->Buffer, str->Length);
            result[str->Length / sizeof(wchar_t)] = L'\0';
            return result;
        }
        return nullptr;
    }

    inline void mb2ws(const char *str, wchar_t *buffer, int bufferSize)
    {
        MultiByteToWideChar(CP_UTF8, 0, str, -1, buffer, bufferSize);
    }

    inline void ws2mb(const wchar_t *wstr, char *buffer, int bufferSize)
    {
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, buffer, bufferSize, nullptr, nullptr);
    }

    inline std::string reverse_sn(std::string serialNumber)
    {
        // Reverse the order of the bytes
        std::reverse(serialNumber.begin(), serialNumber.end());

        // Reverse the order of the byte pairs
        for (size_t i = 0; i < serialNumber.length(); i += 2)
        {
            char temp = serialNumber[i];
            serialNumber[i] = serialNumber[i + 1];
            serialNumber[i + 1] = temp;
        }

        return serialNumber;
    }

    inline bool cert_read_serial_num(CRYPT_INTEGER_BLOB *pSerialNumber, char *serialNumberBuffer, size_t bufferSize)
    {
        DWORD dwFlags = CRYPT_STRING_HEXRAW | CRYPT_STRING_NOCRLF;
        DWORD cbData = 0;

        if (!CryptBinaryToStringA(pSerialNumber->pbData, pSerialNumber->cbData, dwFlags, NULL, &cbData))
            return false;
        if (cbData > bufferSize)
            return false;
        if (!CryptBinaryToStringA(pSerialNumber->pbData, pSerialNumber->cbData, dwFlags, serialNumberBuffer, &cbData))
            return false;

        return true;
    }

    enum class cert_lookup_states : uint8_t
    {
        UNSET = 0,
        FAILED_QUERY_FILE,
        FAILED_QUERY_SIGNER_INFO,
        FAILED_ALLOC_SIGNER_INFO,
        OK,
    };

    struct cert_info_t
    {
        cert_lookup_states lookup_status;
        std::string serial_no;
        std::string name;
        std::string issuer;
    };
    /*
     * Get the certificate info of a signed (or not) file.
     */
    cert_info_t get_cert_info(const char *path);

    struct module_t
    {
        std::string name{};
        std::string path{};

        std::uintptr_t base{};
        std::uintptr_t size{};
    };
    /*
     * Get all modules in given process.
     */
    using module_list = std::vector<module_t>;

    inline module_list get_process_modules(HANDLE process)
    {
        auto snapshot = HANDLE{};

        auto result = module_list();
        auto entry = MODULEENTRY32{};

        auto process_id = GetProcessId(process);

        entry.dwSize = sizeof(entry);

        snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);

        if (!Module32First(snapshot, &entry))
        {
            CloseHandle(snapshot);
            return result;
        }

        do
        {
            auto &info = result.emplace_back();

            info.name = entry.szModule;
            info.path = entry.szExePath;
            info.base = (uintptr_t)entry.modBaseAddr;
            info.size = (uintptr_t)entry.modBaseSize;

        } while (Module32Next(snapshot, &entry));

        CloseHandle(snapshot);

        return result;
    }

    inline uint32_t vft_calc_count(uintptr_t *vft)
    {
        uint32_t result = 0;
        MEMORY_BASIC_INFORMATION mbi;

        for (;;)
        {
            uintptr_t func = vft[result];
            memset(&mbi, 0, sizeof mbi);

            if (!VirtualQuery((void *)func, &mbi, sizeof mbi))
                break;

            if (mbi.Protect != PAGE_EXECUTE_READ &&
                mbi.Protect != PAGE_EXECUTE_READWRITE)
                break;

            result++;
        }

        return result;
    }

    inline bool read_file_into_vec(const std::string &file_path, std::vector<uint8_t> *out_buffer)
    {
        std::ifstream file_ifstream(file_path, std::ios::binary);

        if (!file_ifstream)
            return false;

        out_buffer->assign((std::istreambuf_iterator<char>(file_ifstream)), std::istreambuf_iterator<char>());
        file_ifstream.close();

        return true;
    }

    struct change
    {
        uint32_t rva; // Relative Virtual Address
        uint32_t len; // Length of changed bytes
    };

    inline std::vector<change> diff_binary_data(uint8_t *first, uint8_t *second, size_t length)
    {
        std::vector<change> changes;
        uint32_t rva = 0;
        uint32_t len = 0;

        for (size_t i = 0; i < length; i++)
        {
            if (first[i] != second[i])
            {
                if (len == 0)
                {
                    rva = (uint32_t)i;
                }
                len++;
            }
            else
            {
                if (len > 0)
                {
                    changes.push_back({rva, len});
                    len = 0;
                }
            }
        }

        if (len > 0)
        {
            changes.push_back({rva, len});
        }

        return changes;
    }

    inline void *memmap_file(const char *file_path, size_t *file_size)
    {
        HANDLE fileHandle = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE)
        {
            return NULL;
        }

        HANDLE mappingHandle = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (mappingHandle == NULL)
        {
            CloseHandle(fileHandle);
            return NULL;
        }

        void *fileData = MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, 0);
        if (fileData == NULL)
        {
            CloseHandle(mappingHandle);
            CloseHandle(fileHandle);
            return NULL;
        }

        *file_size = GetFileSize(fileHandle, NULL);

        CloseHandle(mappingHandle);
        CloseHandle(fileHandle);
        return fileData;
    }
}
