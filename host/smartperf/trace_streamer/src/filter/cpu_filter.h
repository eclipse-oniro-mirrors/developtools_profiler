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

#ifndef CPU_FILTER_H
#define CPU_FILTER_H

#include <cstdint>
#include <limits>
#include <map>
#include <string_view>
#include <tuple>

#include "filter_base.h"
#include "trace_data_cache.h"
#include "trace_streamer_filters.h"
#include "ts_common.h"

namespace SysTuning {
namespace TraceStreamer {
class TraceStreamerFilters;
class CpuFilter : private FilterBase {
public:
    CpuFilter(TraceDataCache* dataCache, const TraceStreamerFilters* filter);
    CpuFilter(const CpuFilter&) = delete;
    CpuFilter& operator=(const CpuFilter&) = delete;
    ~CpuFilter() override;

public:
    void InsertSwitchEvent(uint64_t ts,
                           uint64_t cpu,
                           uint64_t prevPid,
                           uint64_t prevPior,
                           uint64_t prevState,
                           uint64_t nextPid,
                           uint64_t nextPior);
    void InsertWakeupEvent(uint64_t ts, uint64_t internalTid);
    bool InsertProcessExitEvent(uint64_t ts, uint64_t cpu, uint64_t pid);
    bool InsertProcessFreeEvent(uint64_t ts, uint64_t pid);
    void Finish() const;
    void Clear();
private:
    void CheckWakeupEvent(uint64_t internalTid);
    uint64_t RemberInternalTidInStateTable(uint64_t uid, uint64_t row, uint64_t state = TASK_INVALID);
    uint64_t RowOfInternalTidInStateTable(uint64_t uid) const;
    uint64_t StateOfInternalTidInStateTable(uint64_t uid) const;
    std::map<uint64_t, uint64_t> cpuToRowThreadState_ = {};
    std::map<uint64_t, uint64_t> cpuToRowSched_ = {};
    std::map<uint64_t, uint64_t> lastWakeUpMsg_ = {};
    struct TPthread {
        uint64_t row_;
        uint64_t state_;
    };
    std::map<uint64_t, TPthread> internalTidToRowThreadState_ = {};
};
} // namespace TraceStreamer
} // namespace SysTuning
#endif // CPU_FILTER_H
