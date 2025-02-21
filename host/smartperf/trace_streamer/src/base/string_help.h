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
#ifndef SRC_TRACE_BASE_STRINGHELP_H
#define SRC_TRACE_BASE_STRINGHELP_H

#include <cstdint>
#include <sys/types.h>
namespace SysTuning {
namespace base {
#if !is_mingw
int memcpy_s(void* dest, uint32_t destSize, const void* src, size_t srcSize);
int sscanf_s(const char* buffer, const char* format, ...);
int strncpy_s(char* strDest, size_t destMax, const char* strSrc, size_t count);
#endif
void* memset_s(void* dest, size_t destSize, int ch, size_t n);
int snprintf_s(char* strDest, size_t destMax, size_t count, const char* format, ...);
int sprintf_s(char* strDest, size_t destMax, const char* format, ...);
} // namespace base
} // namespace SysTuning
#endif // SRC_TRACE_BASE_STRINGHELP_H
