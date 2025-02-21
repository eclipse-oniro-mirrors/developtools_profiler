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

#ifndef INCLUDE_BASE_STRING_TO_NUMERICAL_H_
#define INCLUDE_BASE_STRING_TO_NUMERICAL_H_

#include <iostream>
#include <sstream>
#include <string>

namespace SysTuning {
namespace base {
enum IntegerRadixType {
    INTEGER_RADIX_TYPE_DEC = 10,
    INTEGER_RADIX_TYPE_HEX = 16
};
inline uint16_t GetNameASCIISumNoNum(const std::string& str)
{
    uint32_t sum = 0;
    int len = str.length() - 1;
    while (len >= 0) {
        sum += std::isdigit(str.at(len)) ? 0 : str.at(len);
        len--;
    }
    return sum % INTEGER_RADIX_TYPE_HEX;
}
inline std::optional<uint32_t> StrToUInt32(const std::string& str, int base = INTEGER_RADIX_TYPE_DEC)
{
    if (!str.empty()) {
        char* endPtr = nullptr;
        auto value = static_cast<uint32_t>(std::strtoul(str.c_str(), &endPtr, base));
        if (!*endPtr) {
            return std::make_optional(value);
        }
    }

    return std::nullopt;
}

inline std::string number(uint64_t value, int base = INTEGER_RADIX_TYPE_DEC)
{
    std::stringstream ss;
    if (base == INTEGER_RADIX_TYPE_DEC) {
        ss << std::dec << value;
    } else if (base == INTEGER_RADIX_TYPE_HEX) {
        ss << std::hex << value;
    }
    return ss.str();
}

inline std::optional<int32_t> StrToInt32(const std::string& str, int base = INTEGER_RADIX_TYPE_DEC)
{
    if (!str.empty()) {
        char* endPtr = nullptr;
        auto value = static_cast<int32_t>(std::strtol(str.c_str(), &endPtr, base));
        if (!*endPtr) {
            return std::make_optional(value);
        }
    }

    return std::nullopt;
}

inline std::optional<uint64_t> StrToUInt64(const std::string& str, int base = INTEGER_RADIX_TYPE_DEC)
{
    if (!str.empty()) {
        char* endPtr = nullptr;
        auto value = static_cast<uint64_t>(std::strtoull(str.c_str(), &endPtr, base));
        if (!*endPtr) {
            return std::make_optional(value);
        }
    }

    return std::nullopt;
}

inline std::optional<int64_t> StrToInt64(const std::string& str, int base = INTEGER_RADIX_TYPE_DEC)
{
    if (!str.empty()) {
        char* endPtr = nullptr;
        int64_t value = static_cast<int64_t>(std::strtoll(str.c_str(), &endPtr, base));
        if (!*endPtr) {
            return std::make_optional(value);
        }
    }
    return std::nullopt;
}

inline std::optional<double> StrToDouble(const std::string& str)
{
    if (!str.empty()) {
        double value = std::stod(str);
        return std::make_optional(value);
    }

    return std::nullopt;
}
} // namespace base
} // namespace SysTuning

#endif // INCLUDE_TUNING_EXT_BASE_STRING_UTILS_H_
