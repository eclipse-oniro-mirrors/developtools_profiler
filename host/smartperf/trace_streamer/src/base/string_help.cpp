/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "string_help.h"
#include <cstdio>
#include <string>
#include <memory.h>
#include <vector>
namespace SysTuning {
namespace base {
#define UNUSED(expr)  \
    do {              \
        static_cast<void>(expr); \
    } while (0)
int memcpy_s(void* dest, uint32_t destSize, const void* src, size_t srcSize)
{
    if (srcSize > destSize || src == nullptr || dest == nullptr) {
        return -1;
    } else {
        if (!memcpy(dest, src, srcSize)) {
            printf("memcpy fail\n");
            return -1;
        }
    }
    return 0;
}
#if !is_mingw
int sscanf_s(const char* buffer, const char* format, ...)
{
    va_list ap;
    __builtin_va_start(ap, format);
    int ret = scanf(buffer, format, ap);
    __builtin_va_end(ap);
    return ret;
}

int strncpy_s(char* strDest, size_t destMax, const char* strSrc, size_t count)
{
    return memcpy_s(strDest, destMax, strSrc, count);
}
#endif
void* memset_s(void* dest, size_t destSize, int ch, size_t n)
{
    UNUSED(destSize);
    UNUSED(ch);
    return memset(dest, 0, n);
}

int snprintf_s(char* strDest, size_t destMax, size_t count, const char* format, ...)
{
    UNUSED(count);
    int ret;
    va_list ap;
    __builtin_va_start(ap, format);
    ret = vsnprintf(strDest, destMax, format, ap);
    __builtin_va_end(ap);
    return ret;
}

int sprintf_s(char* strDest, size_t destMax, const char* format, ...)
{
    UNUSED(destMax);
    va_list ap;
    __builtin_va_start(ap, format);
    int ret = sprintf(strDest, format, ap);
    __builtin_va_end(ap);
    return ret;
}
} // namespace base
} // namespace SysTuning
