#pragma once

namespace log
{
    std::vector<uint32_t> _history;
    __forceinline auto flag(const char *fmt, ...)
    {
        va_list vl;
        va_start(vl, fmt);

        // Calculate the required buffer size
        int size = vsnprintf(nullptr, 0, fmt, vl);
        va_end(vl);

        if (size <= 0)
            return; // No need to print if size is zero or negative

        // Allocate a dynamic buffer with the required size (+1 for null terminator)
        std::unique_ptr<char[]> buf(new char[size + 1]);

        va_start(vl, fmt);
        vsnprintf(buf.get(), size + 1, fmt, vl);
        va_end(vl);

        auto crc = tools::mmh32(buf.get(), size, 0);
        bool present = false;

        for (uint32_t val : _history)
        {
            if (val == crc)
            {
                present = true;
                break;
            }
        }

        if (present)
            return;
        _history.push_back(crc);

        printf("%s\n", buf.get());
    }
}
