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
#include "htrace_native_hook_parser.h"
#include "clock_filter.h"
#include "process_filter.h"
#include "stat_filter.h"
namespace SysTuning {
namespace TraceStreamer {
HtraceNativeHookParser::HtraceNativeHookParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx)
    : HtracePluginTimeParser(dataCache, ctx),
      addrToAllocEventRow_(INVALID_UINT64),
      addrToMmapEventRow_(INVALID_UINT64),
      frameToFrameId_(INVALID_UINT64)
{
    invalidLibPathIndexs_.insert(traceDataCache_->dataDict_.GetStringIndex("/system/lib/libc++.so"));
    invalidLibPathIndexs_.insert(traceDataCache_->dataDict_.GetStringIndex("/system/lib64/libc++.so"));
    invalidLibPathIndexs_.insert(traceDataCache_->dataDict_.GetStringIndex("/system/lib/ld-musl-aarch64.so.1"));
    invalidLibPathIndexs_.insert(traceDataCache_->dataDict_.GetStringIndex("/system/lib/ld-musl-arm.so.1"));
}

HtraceNativeHookParser::~HtraceNativeHookParser()
{
    TS_LOGI("native hook data ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(GetPluginStartTime()),
            static_cast<unsigned long long>(GetPluginEndTime()));
    TS_LOGI("native real ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(MinTs()),
            static_cast<unsigned long long>(MaxTs()));
}
// In order to improve the accuracy of data, it is necessary to sort the original data.
// Data sorting will be reduced by 5% to 10% Speed of parsing data.
void HtraceNativeHookParser::SortNativeHookData(BatchNativeHookData& tracePacket)
{
    for (auto i = 0; i < tracePacket.events_size(); i++) {
        auto nativeHookData = std::make_unique<NativeHookData>(*tracePacket.mutable_events(i));
        auto timeStamp = nativeHookData->tv_nsec() + nativeHookData->tv_sec() * SEC_TO_NS;
        tsNativeHookQueue_.insert(std::make_pair(timeStamp, std::move(nativeHookData)));
        MaybeParseNativeHookData();
    }
    return;
}
template <class T1, class T2>
void HtraceNativeHookParser::UpdateMap(std::unordered_map<T1, T2>& sourceMap, T1 key, T2 value)
{
    auto itor = sourceMap.find(key);
    if (itor != sourceMap.end()) {
        itor->second = value;
    } else {
        sourceMap.insert(std::make_pair(key, value));
    }
}
void HtraceNativeHookParser::MaybeParseNativeHookData()
{
    if (tsNativeHookQueue_.size() > MAX_CACHE_SIZE) {
        ParseNativeHookData(tsNativeHookQueue_.begin()->first, tsNativeHookQueue_.begin()->second.get());
        tsNativeHookQueue_.erase(tsNativeHookQueue_.begin());
    }
}
void HtraceNativeHookParser::FinishParseNativeHookData()
{
    for (auto it = tsNativeHookQueue_.begin(); it != tsNativeHookQueue_.end(); it++) {
        ParseNativeHookData(it->first, it->second.get());
    }
    if (traceDataCache_->GetNativeHookData()->Size() == 0) {
        return;
    }
    traceDataCache_->GetNativeHookData()->UpdateMemMapSubType();
    traceDataCache_->GetNativeHookFrameData()->UpdateSymbolId();
    traceDataCache_->GetNativeHookFrameData()->UpdateFileId(filePathIdToFilePathName_);
    std::map<uint64_t, uint64_t> callIdToLastCallerPathIndex;
    traceDataCache_->GetNativeHookFrameData()->GetCallIdToLastLibId(invalidLibPathIndexs_,
                                                                    callIdToLastCallerPathIndex);
    if (callIdToLastCallerPathIndex.size()) {
        traceDataCache_->GetNativeHookData()->UpdateLastCallerPathIndexs(callIdToLastCallerPathIndex);
    }

    UpdateThreadNameWithNativeHookData();
    tsNativeHookQueue_.clear();
    threadNameIdToThreadName_.clear();
    itidToThreadNameId_.clear();
}
void HtraceNativeHookParser::ParseAllocEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData)
{
    auto allocEvent = nativeHookData->alloc_event();
    auto itid = streamFilters_->processFilter_->GetOrCreateThreadWithPid(allocEvent.tid(), allocEvent.pid());
    auto ipid = streamFilters_->processFilter_->GetInternalPid(allocEvent.pid());
    if (allocEvent.thread_name_id() != 0) {
        UpdateMap(itidToThreadNameId_, itid, allocEvent.thread_name_id());
    }
    auto callChainId = ParseNativeHookFrame(allocEvent.frame_info());
    auto row = traceDataCache_->GetNativeHookData()->AppendNewNativeHookData(
        callChainId, ipid, itid, allocEvent.GetTypeName(), INVALID_UINT64, newTimeStamp, 0, 0, allocEvent.addr(),
        allocEvent.size(), allocEvent.size());
    addrToAllocEventRow_.Insert(ipid, allocEvent.addr(), static_cast<uint64_t>(row));
    MaybeUpdateCurrentSizeDur(row, newTimeStamp, true);
}
void HtraceNativeHookParser::ParseFreeEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData)
{
    auto freeEvent = nativeHookData->free_event();
    auto itid = streamFilters_->processFilter_->GetOrCreateThreadWithPid(freeEvent.tid(), freeEvent.pid());
    auto ipid = streamFilters_->processFilter_->GetInternalPid(freeEvent.pid());
    if (freeEvent.thread_name_id() != 0) {
        UpdateMap(itidToThreadNameId_, itid, freeEvent.thread_name_id());
    }
    int64_t freeHeapSize = 0;
    auto row = addrToAllocEventRow_.Find(ipid, freeEvent.addr());
    if (row != INVALID_UINT64 && newTimeStamp > traceDataCache_->GetNativeHookData()->TimeStamData()[row]) {
        addrToAllocEventRow_.Erase(ipid, freeEvent.addr());
        traceDataCache_->GetNativeHookData()->UpdateHeapDuration(row, newTimeStamp);
        freeHeapSize = traceDataCache_->GetNativeHookData()->MemSizes()[row];
    } else if (row == INVALID_UINT64) {
        TS_LOGW("func addr:%lu is empty", freeEvent.addr());
        streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_FREE, STAT_EVENT_DATA_INVALID);
        return;
    }
    auto callChainId = ParseNativeHookFrame(freeEvent.frame_info());
    row = traceDataCache_->GetNativeHookData()->AppendNewNativeHookData(
        callChainId, ipid, itid, freeEvent.GetTypeName(), INVALID_UINT64, newTimeStamp, 0, 0, freeEvent.addr(),
        freeHeapSize, (-1) * freeHeapSize);
    if (freeHeapSize != 0) {
        MaybeUpdateCurrentSizeDur(row, newTimeStamp, true);
    }
}
void HtraceNativeHookParser::ParseMmapEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData)
{
    auto mMapEvent = nativeHookData->mmap_event();
    auto itid = streamFilters_->processFilter_->GetOrCreateThreadWithPid(mMapEvent.tid(), mMapEvent.pid());
    auto ipid = streamFilters_->processFilter_->GetInternalPid(mMapEvent.pid());
    if (mMapEvent.thread_name_id() != 0) {
        UpdateMap(itidToThreadNameId_, itid, mMapEvent.thread_name_id());
    }
    DataIndex subType = INVALID_UINT64;
    if (!mMapEvent.type().empty()) {
        subType = traceDataCache_->dataDict_.GetStringIndex(mMapEvent.type());
        traceDataCache_->GetNativeHookData()->UpdateAddrToMemMapSubType(mMapEvent.addr(), mMapEvent.size(), subType);
    }
    auto callChainId = ParseNativeHookFrame(mMapEvent.frame_info());
    auto row = traceDataCache_->GetNativeHookData()->AppendNewNativeHookData(
        callChainId, ipid, itid, mMapEvent.GetTypeName(), subType, newTimeStamp, 0, 0, mMapEvent.addr(),
        mMapEvent.size(), mMapEvent.size());
    addrToMmapEventRow_.Insert(ipid, mMapEvent.addr(), static_cast<uint64_t>(row));
    MaybeUpdateCurrentSizeDur(row, newTimeStamp, false);
}
void HtraceNativeHookParser::ParseMunmapEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData)
{
    auto mUnMapEvent = nativeHookData->munmap_event();
    auto itid = streamFilters_->processFilter_->GetOrCreateThreadWithPid(mUnMapEvent.tid(), mUnMapEvent.pid());
    auto ipid = streamFilters_->processFilter_->GetInternalPid(mUnMapEvent.pid());
    if (mUnMapEvent.thread_name_id() != 0) {
        UpdateMap(itidToThreadNameId_, itid, mUnMapEvent.thread_name_id());
    }
    auto row = addrToMmapEventRow_.Find(ipid, mUnMapEvent.addr());
    int64_t effectiveMUnMapSize = 0;
    if (row != INVALID_UINT64 && newTimeStamp > traceDataCache_->GetNativeHookData()->TimeStamData()[row]) {
        addrToMmapEventRow_.Erase(ipid, mUnMapEvent.addr());
        traceDataCache_->GetNativeHookData()->UpdateHeapDuration(row, newTimeStamp);
        effectiveMUnMapSize = static_cast<int64_t>(mUnMapEvent.size());
    } else if (row == INVALID_UINT64) {
        TS_LOGW("func addr:%lu is empty", mUnMapEvent.addr());
        streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MUNMAP, STAT_EVENT_DATA_INVALID);
        return;
    }
    auto callChainId = ParseNativeHookFrame(mUnMapEvent.frame_info());
    row = traceDataCache_->GetNativeHookData()->AppendNewNativeHookData(
        callChainId, ipid, itid, mUnMapEvent.GetTypeName(), INVALID_UINT64, newTimeStamp, 0, 0, mUnMapEvent.addr(),
        mUnMapEvent.size(), (-1) * effectiveMUnMapSize);
    if (effectiveMUnMapSize != 0) {
        MaybeUpdateCurrentSizeDur(row, newTimeStamp, false);
    }
}
void HtraceNativeHookParser::ParseTagEvent(const NativeHookData* nativeHookData)
{
    auto memMapTagEvent = nativeHookData->tag_event();
    auto addr = memMapTagEvent.addr();
    auto size = memMapTagEvent.size();
    auto tagIndex = traceDataCache_->dataDict_.GetStringIndex(memMapTagEvent.tag());
    traceDataCache_->GetNativeHookData()->UpdateAddrToMemMapSubType(addr, static_cast<int64_t>(size), tagIndex);
}
void HtraceNativeHookParser::ParseFileEvent(const NativeHookData* nativeHookData)
{
    auto filePathMapMessage = nativeHookData->file_path();
    auto id = filePathMapMessage.id();
    auto nameIndex = traceDataCache_->dataDict_.GetStringIndex(filePathMapMessage.name());
    filePathIdToFilePathName_.insert(std::make_pair(id, nameIndex));
}
void HtraceNativeHookParser::ParseSymbolEvent(const NativeHookData* nativeHookData)
{
    auto symbolMapMessage = nativeHookData->symbol_name();
    auto id = symbolMapMessage.id();
    auto nameIndex = traceDataCache_->dataDict_.GetStringIndex(symbolMapMessage.name());
    traceDataCache_->GetNativeHookFrameData()->UpdateSymbolIdToNameMap(id, nameIndex);
}
void HtraceNativeHookParser::ParseThreadEvent(const NativeHookData* nativeHookData)
{
    auto threadNameMapMessage = nativeHookData->thread_name_map();
    auto id = threadNameMapMessage.id();
    auto nameIndex = traceDataCache_->dataDict_.GetStringIndex(threadNameMapMessage.name());
    UpdateMap(threadNameIdToThreadName_, id, nameIndex);
}

void HtraceNativeHookParser::ParseNativeHookData(const uint64_t timeStamp, const NativeHookData* nativeHookData)
{
    auto eventCase = nativeHookData->event_case();
    uint64_t newTimeStamp = 0;
    if (eventCase >= NativeHookData::kAllocEvent && eventCase <= NativeHookData::kMunmapEvent) {
        newTimeStamp = streamFilters_->clockFilter_->ToPrimaryTraceTime(TS_CLOCK_REALTIME, timeStamp);
        UpdatePluginTimeRange(TS_CLOCK_REALTIME, timeStamp, newTimeStamp);
        switch (eventCase) {
            case NativeHookData::kAllocEvent:
                streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MALLOC, STAT_EVENT_RECEIVED);
                if (newTimeStamp == timeStamp) {
                    streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MALLOC, STAT_EVENT_DATA_INVALID);
                }
                ParseAllocEvent(newTimeStamp, nativeHookData);
                break;
            case NativeHookData::kFreeEvent:
                streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_FREE, STAT_EVENT_RECEIVED);
                if (newTimeStamp == timeStamp) {
                    streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_FREE, STAT_EVENT_DATA_INVALID);
                }
                ParseFreeEvent(newTimeStamp, nativeHookData);
                break;
            case NativeHookData::kMmapEvent:
                streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MMAP, STAT_EVENT_RECEIVED);
                if (newTimeStamp == timeStamp) {
                    streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MMAP, STAT_EVENT_DATA_INVALID);
                }
                ParseMmapEvent(newTimeStamp, nativeHookData);
                break;
            case NativeHookData::kMunmapEvent:
                streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MUNMAP, STAT_EVENT_RECEIVED);
                if (newTimeStamp == timeStamp) {
                    streamFilters_->statFilter_->IncreaseStat(TRACE_NATIVE_HOOK_MUNMAP, STAT_EVENT_DATA_INVALID);
                }
                ParseMunmapEvent(newTimeStamp, nativeHookData);
                break;
            default:
                TS_LOGE("An unknown type of data was received!");
                break;
        }
    } else {
        switch (eventCase) {
            case NativeHookData::kTagEvent:
                ParseTagEvent(nativeHookData);
                break;
            case NativeHookData::kFilePath:
                ParseFileEvent(nativeHookData);
                break;
            case NativeHookData::kSymbolName:
                ParseSymbolEvent(nativeHookData);
                break;
            case NativeHookData::kThreadNameMap:
                ParseThreadEvent(nativeHookData);
                break;
            default:
                TS_LOGE("An unknown type of data was received!");
                break;
        }
    }
}
void HtraceNativeHookParser::MaybeUpdateCurrentSizeDur(uint64_t row, uint64_t timeStamp, bool isMalloc)
{
    auto& lastAnyEventRaw = isMalloc ? lastMallocEventRaw_ : lastMmapEventRaw_;
    if (lastAnyEventRaw != INVALID_UINT64) {
        traceDataCache_->GetNativeHookData()->UpdateCurrentSizeDur(lastAnyEventRaw, timeStamp);
    }
    lastAnyEventRaw = row;
}
uint64_t HtraceNativeHookParser::ParseNativeHookFrame(const RepeatedPtrField<::Frame>& repeatedFrame)
{
    // the callstack from nativehook of sourcedata is reverse order
    // we need to show the last frame firstly
    std::vector<std::unique_ptr<NativeHookFrameTemp>> callStackTemp = {};
    auto depth = 0;
    for (auto i = repeatedFrame.size() - 1; i >= 0; i--) {
        auto frame = repeatedFrame.Get(i);
        DataIndex symbolNameIndex = INVALID_UINT64;
        DataIndex filePathIndex = INVALID_UINT64;
        if (!frame.symbol_name().empty()) {
            symbolNameIndex = traceDataCache_->dataDict_.GetStringIndex(frame.symbol_name().c_str());
            traceDataCache_->GetNativeHookFrameData()->UpdateSymbolIdToNameMap(symbolNameIndex, symbolNameIndex);
        } else if (frame.symbol_name_id()) {
            symbolNameIndex = frame.symbol_name_id();
        }
        if (!frame.file_path().empty()) {
            filePathIndex = traceDataCache_->dataDict_.GetStringIndex(frame.file_path().c_str());
            filePathIdToFilePathName_.insert(std::make_pair(filePathIndex, filePathIndex));
        } else if (frame.file_path_id()) {
            filePathIndex = frame.file_path_id();
        }
        callStackTemp.emplace_back(std::move(std::make_unique<NativeHookFrameTemp>(
            filePathIndex, symbolNameIndex, depth, frame.offset(), frame.symbol_offset())));
        depth++;
    }

    // Determine whether to write callstack data to cache
    auto callChainId = INVALID_UINT64;
    bool callStackNotExist = false;
    auto size = callStackTemp.size();
    for (auto itor = callStackTemp.begin(); itor != callStackTemp.end(); itor++) {
        auto callstack = itor->get();
        auto ret = frameToFrameId_.Find(callstack->fileId_, callstack->symbolId_, callstack->depth_, size);
        if (ret != INVALID_UINT64) { // find it
            if (callChainId == INVALID_UINT64) {
                callChainId = ret;
            } else if (callChainId != ret) {
                callStackNotExist = true;
                break;
            }
        } else { // not find it
            callStackNotExist = true;
            break;
        }
    }
    // write callstack data to cache
    if (callStackNotExist) {
        callChainId = ++callChainId_;
        for (auto itor = callStackTemp.begin(); itor != callStackTemp.end(); itor++) {
            auto callstack = itor->get();
            frameToFrameId_.Insert(callstack->fileId_, callstack->symbolId_, callstack->depth_, callStackTemp.size(),
                                   callChainId);
            traceDataCache_->GetNativeHookFrameData()->AppendNewNativeHookFrame(
                callChainId, callstack->depth_, callstack->ip_, callstack->sp_,
                callstack->symbolId_, callstack->fileId_, callstack->offset_, callstack->symbolOffset_);
        }
    }
    callStackTemp.clear();
    return callChainId;
}
void HtraceNativeHookParser::UpdateThreadNameWithNativeHookData() const
{
    if (itidToThreadNameId_.empty() || threadNameIdToThreadName_.empty()) {
        return;
    }
    for (auto itor = itidToThreadNameId_.begin(); itor != itidToThreadNameId_.end(); ++itor) {
        auto thread = traceDataCache_->GetThreadData(itor->first);
        if (thread->nameIndex_ == 0) {
            auto threadNameMapItor = threadNameIdToThreadName_.find(itor->second);
            if (threadNameMapItor != threadNameIdToThreadName_.end()) {
                thread->nameIndex_ = threadNameMapItor->second;
            }
        }
    }
}
void HtraceNativeHookParser::Finish()
{
    traceDataCache_->MixTraceTime(GetPluginStartTime(), GetPluginEndTime());
}
} // namespace TraceStreamer
} // namespace SysTuning
