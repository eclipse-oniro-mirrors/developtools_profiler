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
#include "ebpf_base.h"

namespace SysTuning {
namespace TraceStreamer {
EbpfBase::EbpfBase(TraceDataCache* dataCache, const TraceStreamerFilters* ctx)
    : EventParserBase(dataCache, ctx),
      pidAndIpToSymbolAndFilePathIndex_(SymbolAndFilePathIndex(false)),
      pidAndipsToCallId_(INVALID_UINT64)
{
}
EbpfBase::~EbpfBase()
{
    pidAndipsToCallId_.Clear();
    pidAndIpToSymbolAndFilePathIndex_.Clear();
}
bool EbpfBase::InitEbpfDataParser(EbpfDataReader* reader)
{
    auto clockId = reader->GetEbpfDataHeader()->header.clock;
    auto itor = ebpfToTSClockType_.find(clockId);
    if (itor == ebpfToTSClockType_.end()) {
        return false;
    }
    clockId_ = ebpfToTSClockType_.at(clockId);
    reader_ = std::move(reader);
    return true;
}

void EbpfBase::ParseCallStackData(const uint64_t* userIpsAddr, uint16_t count, uint32_t pid, uint64_t callId)
{
    uint64_t depth = 0;
    for (auto i = count - 1; i >= 0; i--) {
        if (userIpsAddr[i] > MIN_USER_IP) {
            auto symbolAndFilePathIndex = GetSymbolAndFilePathIndex(pid, userIpsAddr[i]);
            auto ipIndex = ConvertToHexTextIndex(userIpsAddr[i]);
            traceDataCache_->GetEbpfCallStack()->AppendNewData(callId, depth, ipIndex,
                                                               symbolAndFilePathIndex.symbolIndex,
                                                               symbolAndFilePathIndex.filePathIndex);
            depth++;
        }
    }
}

SymbolAndFilePathIndex EbpfBase::GetSymbolAndFilePathIndex(uint32_t pid, uint64_t ip)
{
    auto value = pidAndIpToSymbolAndFilePathIndex_.Find(pid, ip);
    if (value.flag) {
        return value;
    }
    return GetSymbolNameIndexFromElfSym(pid, ip);
}

DataIndex EbpfBase::GetSymbolNameIndexFromSymVaddr(const ElfEventFixedHeader* elfHeaderAddr, uint64_t symVaddr)
{
    uint32_t symbolStart = INVALID_UINT32;
    auto startValueToSymAddr = reader_->GetElfAddrAndStartValueToSymAddr().Find(elfHeaderAddr);
    if (!startValueToSymAddr) {
        return INVALID_UINT64;
    }
    auto end = startValueToSymAddr->upper_bound(symVaddr);
    auto symEntLen = elfHeaderAddr->symEntLen;
    auto length = std::distance(startValueToSymAddr->begin(), end);
    if (length > 0) {
        end--;
        if (symEntLen == ELF32_SYM) {
            auto symbolAddr = reinterpret_cast<const Elf32_Sym*>(end->second);
            if (end->first <= symVaddr && end->first + symbolAddr->st_size >= symVaddr) {
                symbolStart = symbolAddr->st_name;
            }
        } else {
            auto symbolAddr = reinterpret_cast<const Elf64_Sym*>(end->second);
            if (end->first <= symVaddr && end->first + symbolAddr->st_size >= symVaddr) {
                symbolStart = symbolAddr->st_name;
            }
        }
    }

    if (symbolStart == INVALID_UINT32) {
        return INVALID_UINT64;
    }

    // Take out the string according to the subscript
    auto strTabAddr = reinterpret_cast<const char*>(elfHeaderAddr + 1);

    if (symbolStart > elfHeaderAddr->strTabLen) {
        TS_LOGE("symbolStart = %u, elfHeaderAddr->strTabLen = %u", symbolStart, elfHeaderAddr->strTabLen);
        return INVALID_UINT64;
    }

    auto symbolName = reinterpret_cast<const char*>(strTabAddr) + symbolStart;
    return traceDataCache_->GetDataIndex(symbolName);
}

SymbolAndFilePathIndex EbpfBase::GetSymbolNameIndexFromElfSym(uint32_t pid, uint64_t ip)
{
    SymbolAndFilePathIndex symbolAndFilePathIndex(false);

    auto& pidAndStartAddrToMapsAddr = reader_->GetPidAndStartAddrToMapsAddr();
    auto startToMapsAddr = pidAndStartAddrToMapsAddr.Find(pid);
    if (!startToMapsAddr) {
        symbolAndFilePathIndex.flag = true;
        pidAndIpToSymbolAndFilePathIndex_.Insert(pid, ip, symbolAndFilePathIndex);
        return symbolAndFilePathIndex;
    }

    uint64_t vmStart = INVALID_UINT64;
    uint64_t vmOffset = INVALID_UINT64;
    auto end = startToMapsAddr->upper_bound(ip);
    auto length = std::distance(startToMapsAddr->begin(), end);
    if (length > 0) {
        end--;
        if (ip <= end->second->end) {
            vmStart = end->first;
            vmOffset = end->second->offset;
            symbolAndFilePathIndex.filePathIndex =
                traceDataCache_->GetDataIndex(reinterpret_cast<const char*>((end->second) + 1));
        }
    }
    symbolAndFilePathIndex.flag = true;
    if (symbolAndFilePathIndex.filePathIndex == INVALID_INT64) {
        pidAndIpToSymbolAndFilePathIndex_.Insert(pid, ip, symbolAndFilePathIndex);
        return symbolAndFilePathIndex;
    }

    auto itor = reader_->GetElfPathIndexToElfAddr().find(symbolAndFilePathIndex.filePathIndex);
    if (itor == reader_->GetElfPathIndexToElfAddr().end()) {
        pidAndIpToSymbolAndFilePathIndex_.Insert(pid, ip, symbolAndFilePathIndex);
        return symbolAndFilePathIndex;
    }
    uint64_t symVaddr = ip - vmStart + vmOffset + itor->second->textVaddr - itor->second->textOffset;
    auto symbolIndex = GetSymbolNameIndexFromSymVaddr(itor->second, symVaddr);
    if (symbolIndex != INVALID_UINT64) {
        symbolAndFilePathIndex.symbolIndex = symbolIndex;
    }
    pidAndIpToSymbolAndFilePathIndex_.Insert(pid, ip, symbolAndFilePathIndex);
    return symbolAndFilePathIndex;
}

DataIndex EbpfBase::ConvertToHexTextIndex(uint64_t number)
{
    if (number == INVALID_UINT64) {
        return number;
    }
    std::string str = "0x" + base::number(number, base::INTEGER_RADIX_TYPE_HEX);
    return traceDataCache_->GetDataIndex(str.c_str());
}
} // namespace TraceStreamer
} // namespace SysTuning
