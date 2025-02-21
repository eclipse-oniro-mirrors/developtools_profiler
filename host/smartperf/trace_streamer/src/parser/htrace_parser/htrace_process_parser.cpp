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
#include "htrace_process_parser.h"
#include "clock_filter.h"
#include "htrace_event_parser.h"
#include "process_filter.h"
#include "stat_filter.h"
namespace SysTuning {
namespace TraceStreamer {
HtraceProcessParser::HtraceProcessParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx)
    : HtracePluginTimeParser(dataCache, ctx)
{
}

HtraceProcessParser::~HtraceProcessParser()
{
    TS_LOGI("process ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(GetPluginStartTime()),
            static_cast<unsigned long long>(GetPluginEndTime()));
    TS_LOGI("process real ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(MinTs()),
            static_cast<unsigned long long>(MaxTs()));
}
void HtraceProcessParser::Parse(ProcessData& tracePacket, uint64_t ts)
{
    for (int i = 0; i < tracePacket.processesinfo_size(); ++i) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_PROCESS, STAT_EVENT_START);
        auto processesInfo = tracePacket.processesinfo(i);
        auto pssInfo = processesInfo.pssinfo();
        auto cpuInfo = CpuInfo();
        if (processesInfo.has_cpuinfo()) {
            cpuInfo = processesInfo.cpuinfo();
        }
        auto liveProcess = std::make_unique<TsLiveProcessData>();
        auto diskio = processesInfo.diskinfo();
        liveProcess->SetLiveProcess(ts, processesInfo, cpuInfo, pssInfo, diskio);
        liveProcessData_.push_back(std::move(liveProcess));
    }
}
void HtraceProcessParser::Finish()
{
    if (!liveProcessData_.size()) {
        TS_LOGW("process no data");
        return;
    }
    auto cmp = [](const std::unique_ptr<TsLiveProcessData>& a, const std::unique_ptr<TsLiveProcessData>& b) {
        return a->ts_ < b->ts_;
    };
    std::sort(liveProcessData_.begin(), liveProcessData_.end(), cmp);
    bool first = true;
    uint64_t lastTs = 0;
    for (auto itor = liveProcessData_.begin(); itor != liveProcessData_.end(); itor++) {
        auto tsOld = (*itor)->ts_;
        (*itor)->ts_ = streamFilters_->clockFilter_->ToPrimaryTraceTime(TS_CLOCK_REALTIME, (*itor)->ts_);
        UpdatePluginTimeRange(TS_CLOCK_REALTIME, tsOld, (*itor)->ts_);
        if (first) {
            lastTs = (*itor)->ts_;
            first = false;
            continue;
        }
        auto dur = (*itor)->ts_ - lastTs;
        lastTs = (*itor)->ts_;
        if (!(*itor)->processInfo_->pid()) {
            continue;
        }
        traceDataCache_->GetLiveProcessData()->AppendNewData(
            (*itor)->ts_, dur, (*itor)->processInfo_->pid(), (*itor)->processInfo_->name(),
            (*itor)->processInfo_->ppid(), (*itor)->processInfo_->uid(), std::to_string((*itor)->processInfo_->uid()),
            (*itor)->cpuUsageData_->cpu_usage(), (*itor)->pssInfo_->pss_info(), (*itor)->cpuUsageData_->cpu_time_ms(),
            (*itor)->cpuUsageData_->thread_sum(), (*itor)->diskio_->wbytes(), (*itor)->diskio_->rbytes());
    }
    liveProcessData_.clear();
    traceDataCache_->MixTraceTime(GetPluginStartTime(), GetPluginEndTime());
}
} // namespace TraceStreamer
} // namespace SysTuning
