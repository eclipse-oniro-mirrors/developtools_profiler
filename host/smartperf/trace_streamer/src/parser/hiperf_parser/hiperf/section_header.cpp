/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <elf_parser.h>

using namespace OHOS::Developtools::HiPerf::ELF;
namespace OHOS {
namespace Developtools {
namespace HiPerf {
enum class NUMBER : int {
    NUMBER_ZERO = 0,
    NUMBER_ONE = 1,
    NUMBER_TWO = 2,
    NUMBER_THREE = 3,
    NUMBER_FOUR = 4,
    NUMBER_FIVE = 5,
    NUMBER_SIX = 6,
    NUMBER_SEVEN = 7,
    NUMBER_EIGHT = 8,
    NUMBER_NINE = 9,
    NUMBER_TEN = 10,
    NUMBER_ELEVEN = 11,
    NUMBER_TWELVE = 12,
};

std::unique_ptr<SectionHeader> SectionHeader::MakeUnique(char * const shdrBuf, const size_t bufSize,
                                                         const size_t index)
{
    std::unique_ptr<SectionHeader> shdr {new (std::nothrow) SectionHeader()};
    if (shdr == nullptr) {
        return nullptr;
    }
    if (!shdr->Init(shdrBuf, bufSize, index)) {
        HLOGE("SectionHeader::Init(shdrBuf, bufSize, index) failed");
        DumpShdrBuf(shdrBuf, bufSize);
        return nullptr;
    }
    return shdr;
}

bool SectionHeader::ParseSecHeader32(char * const shdrBuf)
{
    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(shdrBuf);
    int index {0};
    nameIndex_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_ONE);
    secType_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_TWO);
    secFlags_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_SIX);
    link_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_SEVEN);
    info_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_THREE);
    secVaddr_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_FOUR);
    fileOffset_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_FIVE);
    secSize_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_EIGHT);
    secAddrAlign_ = u4Buf[index];
    index = static_cast<int>(NUMBER::NUMBER_NINE);
    secEntrySize_ = u4Buf[index];
    return true;
}

bool SectionHeader::ParseSecHeader64(char * const shdrBuf)
{
    uint64_t *u8Buf = reinterpret_cast<uint64_t *>(shdrBuf);
    uint32_t *u4Buf = reinterpret_cast<uint32_t *>(shdrBuf);
    size_t index {0};
    nameIndex_ = u4Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_ONE);
    secType_ = u4Buf[index];
    secFlags_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_TEN);
    link_ = u4Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_ELEVEN);
    info_ = u4Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_TWO);
    secVaddr_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_THREE);
    fileOffset_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_FOUR);
    secSize_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_SIX);
    secAddrAlign_ = u8Buf[index];
    index = static_cast<size_t>(NUMBER::NUMBER_SEVEN);
    secEntrySize_ = u8Buf[index];
    return true;
}
} // namespace HiPerf
} // namespace Developtools
} // namespace OHOS
