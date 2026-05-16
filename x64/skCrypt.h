#pragma once
#include <string>
#include <array>
#include <windows.h>
#include <intrin.h>

namespace skc
{

    __forceinline bool check_hw_breakpoints()
    {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx))
        {
            return (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0);
        }
        return false;
    }


    __forceinline bool check_debugger()
    {
#ifdef _WIN64
        unsigned char being_debugged = *(unsigned char*)(__readgsqword(0x60) + 2);
        unsigned long nt_global_flag = *(unsigned long*)(__readgsqword(0x60) + 0xBC);
        if (being_debugged || (nt_global_flag & 0x70)) return true;
#endif
        return check_hw_breakpoints();
    }

    template<std::size_t N, char K1, char K2, char K3>
    class sk_string
    {
    private:
        volatile char _storage[N];

    public:
        __forceinline constexpr sk_string(const char* str) : _storage{ 0 }
        {
            for (std::size_t i = 0; i < N; ++i)
                const_cast<char&>(_storage[i]) = str[i] ^ K1 ^ (K2 + i) ^ K3;
        }

        __forceinline std::string decrypt()
        {

            float junk_math = 1337.0f;
            for (int i = 0; i < 5; i++) junk_math = (junk_math * i) / (i + 1);
            if (junk_math < -1.0f) return "error";

            char k1 = K1;
            char k2 = K2;
            char k3 = K3;


            if (check_debugger())
            {
                k1 ^= 0x33;
                k2 ^= 0x55;
                k3 ^= 0x77;
            }

            std::string output;
            output.reserve(N - 1);
            for (std::size_t i = 0; i < N - 1; i++)
            {
                char c = _storage[i];
                c ^= k1;
                c ^= (k2 + i);
                c ^= k3;
                output.push_back(c);
            }


            for (std::size_t i = 0; i < N; i++)
            {
                const_cast<char&>(_storage[i]) = 0x00;
            }

            return output;
        }
    };
}


#define skCrypt(str) skc::sk_string<sizeof(str), \
    static_cast<char>((__TIME__[7] * 127) ^ 0xAD), \
    static_cast<char>((__TIME__[4] * 103) ^ 0x77), \
    static_cast<char>((__TIME__[3] * 97) ^ 0x33)>(str)
