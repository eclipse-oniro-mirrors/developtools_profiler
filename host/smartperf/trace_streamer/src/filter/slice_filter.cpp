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

#include "slice_filter.h"
#include <cstdint>
#include <limits>
#include <optional>

#include "args_filter.h"
#include "log.h"
#include "measure_filter.h"
#include "process_filter.h"
#include "stat_filter.h"
#include "string_to_numerical.h"
#include "ts_common.h"

namespace SysTuning {
namespace TraceStreamer {
using namespace SysTuning::base;
SliceFilter::SliceFilter(TraceDataCache* dataCache, const TraceStreamerFilters* filter)
    : FilterBase(dataCache, filter), asyncEventMap_(INVALID_UINT64)
{
}

SliceFilter::~SliceFilter() = default;

size_t SliceFilter::BeginSlice(const std::string& comm,
                               uint64_t timestamp,
                               uint32_t pid,
                               uint32_t threadGroupId,
                               DataIndex cat,
                               DataIndex nameIndex)
{
    InternalTid internalTid = INVALID_UTID;
    if (threadGroupId > 0) {
        internalTid = streamFilters_->processFilter_->UpdateOrCreateThreadWithPidAndName(pid, threadGroupId, comm);
        pidTothreadGroupId_[pid] = threadGroupId;
    } else {
        internalTid = streamFilters_->processFilter_->UpdateOrCreateThreadWithName(timestamp, pid, comm);
    }
    // make a SliceData DataItem, {timestamp, dur, internalTid, cat, nameIndex}
    struct SliceData sliceData = {timestamp, -1, internalTid, cat, nameIndex};
    ArgsSet args;
    return StartSlice(timestamp, pid, cat, nameIndex, args, sliceData);
}

void SliceFilter::IrqHandlerEntry(uint64_t timestamp, uint32_t cpu, DataIndex catalog, DataIndex nameIndex)
{
    struct SliceData sliceData = {timestamp, 0, cpu, catalog, nameIndex};
    auto slices = traceDataCache_->GetIrqData();
    size_t index = slices->AppendInternalSlice(
        sliceData.timestamp, sliceData.duration, sliceData.internalTid, sliceData.cat,
        GetNameASCIISumNoNum(traceDataCache_->GetDataFromDict(sliceData.name)), sliceData.name, 0, std::nullopt);
    if (irqEventMap_.count(cpu)) {
        // not match
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_IRQ_HANDLER_ENTRY, STAT_EVENT_DATA_LOST);
        irqEventMap_.at(cpu) = {timestamp, index};
    } else {
        irqEventMap_[cpu] = {timestamp, index};
    }
    return;
}

void SliceFilter::IrqHandlerExit(uint64_t timestamp, uint32_t cpu, ArgsSet args)
{
    if (!irqEventMap_.count(cpu)) {
        // not match
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_IRQ_HANDLER_EXIT, STAT_EVENT_NOTMATCH);
        return;
    }
    uint32_t argSetId = INVALID_UINT32;
    auto slices = traceDataCache_->GetIrqData();
    argSetId = streamFilters_->argsFilter_->NewArgs(args);
    slices->SetIrqDurAndArg(irqEventMap_.at(cpu).row, timestamp, argSetId);
    irqEventMap_.erase(cpu);
    return;
}

void SliceFilter::SoftIrqEntry(uint64_t timestamp, uint32_t cpu, DataIndex catalog, DataIndex nameIndex)
{
    struct SliceData sliceData = {timestamp, 0, cpu, catalog, nameIndex};
    auto slices = traceDataCache_->GetIrqData();
    size_t index = slices->AppendInternalSlice(
        sliceData.timestamp, sliceData.duration, sliceData.internalTid, sliceData.cat,
        GetNameASCIISumNoNum(traceDataCache_->GetDataFromDict(sliceData.name)), sliceData.name, 0, std::nullopt);
    if (softIrqEventMap_.count(cpu)) {
        // not match
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SOFTIRQ_ENTRY, STAT_EVENT_DATA_LOST);
        softIrqEventMap_.at(cpu) = {timestamp, index};
    } else {
        softIrqEventMap_[cpu] = {timestamp, index};
    }
    return;
}

void SliceFilter::SoftIrqExit(uint64_t timestamp, uint32_t cpu, ArgsSet args)
{
    if (!softIrqEventMap_.count(cpu)) {
        // not match
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SOFTIRQ_EXIT, STAT_EVENT_DATA_LOST);
        return;
    }
    uint32_t argSetId = INVALID_UINT32;
    auto slices = traceDataCache_->GetIrqData();
    argSetId = streamFilters_->argsFilter_->NewArgs(args);
    slices->SetIrqDurAndArg(softIrqEventMap_.at(cpu).row, timestamp, argSetId);
    softIrqEventMap_.erase(cpu);
    return;
}

void SliceFilter::RememberSliceData(InternalTid internalTid,
                                    std::unordered_map<InternalTid, StackOfSlices>& stackMap,
                                    SliceData& slice,
                                    uint32_t depth,
                                    uint64_t index)
{
    if (stackMap.find(internalTid) == stackMap.end()) {
        auto& sliceStack = stackMap[internalTid].sliceStack; // this can be a empty call, but it does not matter
        slice.depth = depth;
        slice.index = index;
        sliceStack.push_back(slice);
    } else {
        auto& sliceStack = stackMap.at(internalTid).sliceStack; // this can be a empty call, but it does not matter
        slice.depth = depth;
        slice.index = index;
        sliceStack.push_back(slice);
    }
}
size_t SliceFilter::AsyncBinder(uint64_t timestamp, uint32_t pid, DataIndex cat, DataIndex nameIndex, ArgsSet& args)
{
    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(timestamp, pid);
    struct SliceData sliceData = {timestamp, 0, internalTid, cat, nameIndex};
    return StartSlice(timestamp, pid, cat, nameIndex, args, std::move(sliceData));
}
uint8_t SliceFilter::CurrentDepth(InternalTid internalTid)
{
    if (depthHolder_.find(internalTid) == depthHolder_.end()) {
        return 0;
    }
    auto& depthMap = depthHolder_.at(internalTid);
    auto depthSize = depthMap.size();
    auto lastIndex = 0;
    for (int32_t i = depthSize - 1; i >= 0; i--) {
        if (depthMap.at(i)) {
            return i;
        }
    }
    return 0;
}
uint8_t SliceFilter::UpdateDepth(bool increase, InternalTid internalTid, int32_t depth)
{
    if (increase) {
        if (depthHolder_.find(internalTid) == depthHolder_.end()) {
            StackOnDepth tmp;
            tmp.insert(std::make_pair(0, true));
            depthHolder_.insert(std::make_pair(internalTid, tmp));
            return 0;
        }
        auto& depthMap = depthHolder_.at(internalTid);
        auto depthSize = depthMap.size();
        auto lastIndex = 0;
        for (int32_t i = depthSize - 1; i >= 0; i--) {
            if (depthMap.at(i) && (i == depthSize - 1)) {
                depthMap.insert(std::make_pair(depthSize, true));
                return depthSize;
            }
            if (depthMap.at(i)) {
                break;
            }
            lastIndex = i;
        }

        if (!depthMap.at(lastIndex)) {
            depthMap.at(lastIndex) = true;
            return lastIndex;
        }
    } else {
        if (depthHolder_.find(internalTid) == depthHolder_.end()) {
            TS_LOGE("internalTid not found");
            return 0;
        }
        auto& depthMap = depthHolder_.at(internalTid);
        if (depthMap.find(depth) == depthMap.end()) {
            return 0;
        }
        depthMap.at(depth) = false;
    }
    return depth;
}

void SliceFilter::CloseUnMatchedSlice(int64_t ts, SlicesStack& stack, InternalTid itid)
{
    auto slices = traceDataCache_->GetInternalSlicesData();
    bool incomplete = false;
    for (int i = stack.size() - 1; i >= 0; i--) {
        uint32_t sliceIdx = stack[i].index;
        int64_t startTs = slices->TimeStamData()[sliceIdx];
        int64_t dur = slices->DursData()[sliceIdx];
        int64_t endTs = startTs + dur;
        if (dur == -1) {
            incomplete = true;
            continue;
        }
        if (incomplete) {
            if (ts <= endTs) {
                continue;
            }
            for (int j = stack.size() - 1; j > i; --j) {
                uint32_t childIdx = stack[i].index;
                slices->SetDur(childIdx, endTs - slices->TimeStamData()[childIdx]);
                stack.pop_back();
            }
            stack.pop_back();
            incomplete = false;
            continue;
        }
        if (endTs <= ts) {
            stack.pop_back();
        }
    }
}

int32_t SliceFilter::MatchingIncompleteSliceIndex(const SlicesStack& stack, DataIndex category, DataIndex name)
{
    auto slices = traceDataCache_->GetInternalSlicesData();
    for (int i = stack.size() - 1; i >= 0; i--) {
        uint32_t sliceIdx = stack[i].index;
        if (slices->DursData()[sliceIdx] != -1) {
            continue;
        }
        const DataIndex& categoryLast = slices->CatsData()[sliceIdx];
        if (category != INVALID_UINT64 && (categoryLast != INVALID_UINT64 && category != categoryLast)) {
            continue;
        }
        const DataIndex& nameLast = slices->NamesData()[sliceIdx];
        if (name != INVALID_UINT64 && nameLast != INVALID_UINT64 && name != nameLast) {
            continue;
        }
        return static_cast<int32_t>(i);
    }
    return -1;
}
size_t SliceFilter::StartSlice(
    uint64_t timestamp, uint32_t pid, DataIndex cat, DataIndex nameIndex, ArgsSet& args, SliceData sliceData)
{
    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(timestamp, pid);
    auto& sliceStack = binderStackMap_[internalTid];
    auto& stack = sliceStack.sliceStack;
    if (sliceStack.isAsyncEvent) {
        sliceStack.asyncEventCount++;
        sliceStack.asyncEventLastBeginTs = timestamp;
        if (!stack.empty()) {
            return INVALID_UINT32;
        }
    }
    // keep slice of thread
    CloseUnMatchedSlice(timestamp, stack, internalTid);
    uint32_t depth = stack.size();
    auto slices = traceDataCache_->GetInternalSlicesData();
    uint32_t parentId = depth == 0 ? INVALID_UINT32 : slices->IdsData()[stack.back().index];
        
    size_t index = slices->AppendInternalSlice(
        sliceData.timestamp, sliceData.duration, sliceData.internalTid, sliceData.cat,
        GetNameASCIISumNoNum(traceDataCache_->GetDataFromDict(sliceData.name)), sliceData.name, 0, parentId);
    if (depth >= std::numeric_limits<uint8_t>::max()) {
        return INVALID_UINT32;
    }
    slices->SetDepth(index, depth);

    uint32_t argSetId = INVALID_UINT32;
    if (args.valuesMap_.size()) {
        if (args.inserted_) {
            argSetId = args.argSetId_;
        } else {
            argSetId = streamFilters_->argsFilter_->NewArgs(args);
            sliceRowToArgsSetId_[index] = argSetId;
            argsSetIdToSliceRow_[argSetId] = static_cast<uint32_t>(index);
            args.argSetId_ = argSetId;
            args.inserted_ = true;
        }
        // set ArgSetId here
        slices->SetArgSetId(index, argSetId);
    }
    sliceData.argSetId = argSetId;
    RememberSliceData(sliceData.internalTid, binderStackMap_, sliceData, depth, index);
    return index;
}
size_t SliceFilter::BeginBinder(uint64_t timestamp, uint32_t pid, DataIndex cat, DataIndex nameIndex, ArgsSet args)
{
    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(timestamp, pid);
    struct SliceData sliceData = {timestamp, -1, internalTid, cat, nameIndex};
    return StartSlice(timestamp, pid, cat, nameIndex, args, std::move(sliceData));
}

size_t SliceFilter::CompleteSlice(uint64_t timestamp, uint32_t pid, DataIndex category, DataIndex name, ArgsSet args)
{
    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(timestamp, pid);
    if (binderStackMap_.find(internalTid) == binderStackMap_.end()) {
        return INVALID_INT32;
    }
    auto& stackInfo = binderStackMap_[internalTid];
    SlicesStack& stack = stackInfo.sliceStack;
    CloseUnMatchedSlice(timestamp, stack, internalTid);
    if (stack.empty()) {
        TS_LOGE("a slice end do not match a slice start event");
        callEventDisMatchCount++;
        return INVALID_INT32;
    }
    auto stackIdx = MatchingIncompleteSliceIndex(stack, category, name);
    if (stackIdx < 0) {
        TS_LOGE("MatchingIncompleteSliceIndex failed");
        return INVALID_INT32;
    }
    auto lastRow = stack[stackIdx].index;
    auto slices = traceDataCache_->GetInternalSlicesData();
    slices->SetDuration(lastRow, timestamp);

    auto argSize = sliceRowToArgsSetId_.count(lastRow);
    size_t argSetId = 0;
    if (args.valuesMap_.size()) {
        if (!argSize) {
            argSetId = streamFilters_->argsFilter_->NewArgs(args);
            sliceRowToArgsSetId_[lastRow] = argSetId;
            slices->SetArgSetId(lastRow, argSetId);
        } else {
            argSetId = sliceRowToArgsSetId_.at(lastRow);
        }
        streamFilters_->argsFilter_->AppendArgs(args, argSetId);
    }
    if (stackInfo.isAsyncEvent) {
        ArgsSet args;
        args.AppendArg(asyncBeginCountId_, BASE_DATA_TYPE_INT, stackInfo.asyncEventCount);
        args.AppendArg(asyncBeginTsId_, BASE_DATA_TYPE_INT, stackInfo.asyncEventLastBeginTs);
        if (!argSetId) {
            argSetId = streamFilters_->argsFilter_->NewArgs(args);
            sliceRowToArgsSetId_[lastRow] = argSetId;
            slices->SetArgSetId(lastRow, argSetId);
        } else {
            streamFilters_->argsFilter_->AppendArgs(args, argSetId);
        }
    }
    if (stackIdx == stack.size() - 1) {
        stack.pop_back();
    }
    streamFilters_->processFilter_->AddThreadSliceNum(internalTid);
    return lastRow;
}
size_t SliceFilter::EndBinder(uint64_t timestamp, uint32_t pid, DataIndex category, DataIndex name, ArgsSet args)
{
    return CompleteSlice(timestamp, pid, category, name, args);
}
std::tuple<uint64_t, uint32_t> SliceFilter::AddArgs(uint32_t tid, DataIndex key1, DataIndex key2, ArgsSet& args)
{
    InternalTid internalTid = streamFilters_->processFilter_->GetInternalTid(tid);
    if (binderStackMap_.find(internalTid) == binderStackMap_.end()) {
        return std::make_tuple(INVALID_UINT32, INVALID_UINT32);
    }
    auto& stack = binderStackMap_[internalTid];
    auto idx = MatchingIncompleteSliceIndex(stack.sliceStack, key1, key2);
    if (idx < 0) {
        return std::make_tuple(INVALID_UINT32, INVALID_UINT32);
    }
    uint32_t argSetId = stack.sliceStack[idx].argSetId;
    if (argSetId == INVALID_UINT32) {
        argSetId = streamFilters_->argsFilter_->NewArgs(args);
        sliceRowToArgsSetId_[stack.sliceStack[idx].index] = argSetId;
        stack.sliceStack[idx].argSetId = argSetId;
    } else {
        streamFilters_->argsFilter_->AppendArgs(args, argSetId);
    }
    return std::make_tuple(stack.sliceStack[idx].index, argSetId);
}
void SliceFilter::StartAsyncSlice(uint64_t timestamp,
                                  uint32_t pid,
                                  uint32_t threadGroupId,
                                  uint64_t cookie,
                                  DataIndex nameIndex)
{
    UNUSED(pid);
    InternalPid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(timestamp, threadGroupId);

    auto lastFilterId = asyncEventMap_.Find(internalTid, cookie, nameIndex);
    auto slices = traceDataCache_->GetInternalSlicesData();
    if (lastFilterId != INVALID_UINT64) {
        asyncEventDisMatchCount++;
        return;
    }
    asyncEventSize_++;
    // a pid, cookie and function name determain a callstack
    asyncEventMap_.Insert(internalTid, cookie, nameIndex, asyncEventSize_);
    // the IDE need a depth to paint call slice in different position of the canvas, the depth of async call
    // do not mean the parent-to-child relationship, it is different from no-async call
    uint8_t depth = 0;
    size_t index = slices->AppendInternalAsyncSlice(timestamp, -1, internalTid, INVALID_UINT64,
                                                    GetNameASCIISumNoNum(traceDataCache_->GetDataFromDict(nameIndex)),
                                                    nameIndex, depth, cookie, std::nullopt);
    asyncEventFilterMap_.insert(std::make_pair(asyncEventSize_, AsyncEvent{timestamp, index}));
}

void SliceFilter::FinishAsyncSlice(uint64_t timestamp,
                                   uint32_t pid,
                                   uint32_t threadGroupId,
                                   uint64_t cookie,
                                   DataIndex nameIndex)
{
    UNUSED(pid);
    InternalPid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(timestamp, threadGroupId);
    auto lastFilterId = asyncEventMap_.Find(internalTid, cookie, nameIndex);
    auto slices = traceDataCache_->GetInternalSlicesData();
    if (lastFilterId == INVALID_UINT64) { // if failed
        asyncEventDisMatchCount++;
        return;
    }
    if (asyncEventFilterMap_.find(lastFilterId) == asyncEventFilterMap_.end()) {
        TS_LOGE("logic error");
        asyncEventDisMatchCount++;
        return;
    }
    // update timestamp
    asyncEventFilterMap_.at(lastFilterId).timestamp = timestamp;
    slices->SetDuration(asyncEventFilterMap_.at(lastFilterId).row, timestamp);
    asyncEventFilterMap_.erase(lastFilterId);
    asyncEventMap_.Erase(internalTid, cookie, nameIndex);
    streamFilters_->processFilter_->AddThreadSliceNum(internalTid);
}


size_t SliceFilter::EndSlice(
    uint64_t timestamp, uint32_t pid, uint32_t threadGroupId, DataIndex category, DataIndex name)
{
    return CompleteSlice(timestamp, pid, category, name);
}

void SliceFilter::Clear()
{
    asyncEventMap_.Clear();
    asyncNoEndingEventMap_.clear();
    irqEventMap_.clear();
    softIrqEventMap_.clear();
    asyncEventFilterMap_.clear();
    sliceStackMap_.clear();
    depthHolder_.clear();
    sliceRowToArgsSetId_.clear();
    argsSetIdToSliceRow_.clear();
    argsSetIdToSliceRow_.clear();
    argsSet_.clear();
}
} // namespace TraceStreamer
} // namespace SysTuning
