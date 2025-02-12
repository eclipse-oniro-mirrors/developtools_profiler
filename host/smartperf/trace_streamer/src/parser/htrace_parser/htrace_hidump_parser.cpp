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
#include "htrace_hidump_parser.h"
#include "clock_filter.h"
#include "htrace_event_parser.h"
#include "process_filter.h"
#include "stat_filter.h"
namespace SysTuning {
namespace TraceStreamer {
HtraceHidumpParser::HtraceHidumpParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx)
    : HtracePluginTimeParser(dataCache, ctx) {}

HtraceHidumpParser::~HtraceHidumpParser()
{
    TS_LOGI("Fps data ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(GetPluginStartTime()),
            static_cast<unsigned long long>(GetPluginEndTime()));
}
void HtraceHidumpParser::Parse(HidumpInfo& tracePacket)
{
    if (!tracePacket.fps_event_size()) {
        return;
    }
    for (int i = 0; i < tracePacket.fps_event_size(); i++) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_HIDUMP_FPS, STAT_EVENT_RECEIVED);
        auto hidumpData = tracePacket.mutable_fps_event(i);
        auto timeStamp = hidumpData->time().tv_nsec() + hidumpData->time().tv_sec() * SEC_TO_NS;
        auto newTimeStamp = streamFilters_->clockFilter_->ToPrimaryTraceTime(hidumpData->id(), timeStamp);
        UpdatePluginTimeRange(hidumpData->id(), timeStamp, newTimeStamp);
        clockId_ = hidumpData->id();
        auto fps = hidumpData->fps();
        traceDataCache_->GetHidumpData()->AppendNewHidumpInfo(newTimeStamp, fps);
    }
}
void HtraceHidumpParser::Finish()
{
    traceDataCache_->MixTraceTime(GetPluginStartTime(), GetPluginEndTime());
}
} // namespace TraceStreamer
} // namespace SysTuning
