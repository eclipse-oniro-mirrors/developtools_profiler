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

#include "clock_filter.h"
#include <algorithm>
#include <map>

namespace SysTuning {
namespace TraceStreamer {
ClockFilter::ClockFilter(TraceDataCache* dataCache, const TraceStreamerFilters* filter)
    : FilterBase(dataCache, filter), primaryClock_(BuiltinClocks::TS_CLOCK_BOOTTIME), dataCache_(dataCache)
{
}

ClockFilter::~ClockFilter() {}

std::string ClockFilter::GenClockKey(ClockId srcClockId, ClockId desClockId)
{
    std::string ret;
    ret += std::to_string(srcClockId);
    ret += ",";
    ret += std::to_string(desClockId);
    return ret;
}

uint64_t ClockFilter::ToPrimaryTraceTime(ClockId srcClockId, uint64_t srcTs) const
{
    if (srcClockId == primaryClock_) {
        return srcTs;
    }
    return Convert(srcClockId, srcTs, primaryClock_);
}

uint64_t ClockFilter::Convert(ClockId srcClockId, uint64_t srcTs, ClockId desClockId) const
{
    std::string&& clockKey = GenClockKey(srcClockId, desClockId);
    auto keyIt = clockMaps_.find(clockKey);
    if (keyIt == clockMaps_.end()) {
        return srcTs;
    }

    auto tsIt = keyIt->second.upper_bound(srcTs);
    if (tsIt != keyIt->second.begin()) {
        tsIt--;
    }

    if (tsIt->second >= 0) {
        return srcTs + static_cast<uint64_t>(tsIt->second);
    } else {
        return srcTs - static_cast<uint64_t>(0 - tsIt->second);
    }
}

void ClockFilter::AddConvertClockMap(ClockId srcClockId, ClockId dstClockId, uint64_t srcTs, uint64_t dstTs)
{
    std::string&& clockKey = GenClockKey(srcClockId, dstClockId);
    auto keyIt = clockMaps_.find(clockKey);
    if (keyIt == clockMaps_.end()) {
        ConvertClockMap newConvertMap = {{srcTs, dstTs - srcTs}};
        clockMaps_[clockKey] = newConvertMap;
    } else {
        clockMaps_[clockKey].insert(std::make_pair(srcTs, dstTs - srcTs));
    }
}

void ClockFilter::AddClockSnapshot(const std::vector<SnapShot>& snapShot)
{
    ClockId srcId, desId;
    const int theDataBeforeLast = 2;
    for (srcId = 0; srcId < snapShot.size() - 1; srcId++) {
        ClockId srcClockId = snapShot[srcId].clockId;
        uint64_t srcTs = snapShot[srcId].ts;
        traceDataCache_->GetClockSnapshotData()->AppendNewSnapshot(srcClockId,
                                                                   srcTs, dataCache_->GetConstStatAndInfo().clockid2ClockNameMap_.at(static_cast<BuiltinClocks>(srcClockId)));
        for (desId = srcId + 1; desId < snapShot.size(); desId++) {
            ClockId desClockId = snapShot[desId].clockId;
            uint64_t desTs = snapShot[desId].ts;
            if ((srcId == snapShot.size() - theDataBeforeLast) and (desId == snapShot.size() - 1)) {
                traceDataCache_->GetClockSnapshotData()->AppendNewSnapshot(desClockId, desTs,
                                                                           dataCache_->GetConstStatAndInfo().clockid2ClockNameMap_.at(static_cast<BuiltinClocks>(desClockId)));
            }
            AddConvertClockMap(srcClockId, desClockId, srcTs, desTs);
            AddConvertClockMap(desClockId, srcClockId, desTs, srcTs);
        }
    }
    hasInitSnapShot_ = true;
}
} // namespace TraceStreamer
} // namespace SysTuning
