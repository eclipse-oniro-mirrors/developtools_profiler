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
#ifndef HTRACE_PROCESS_PARSER_H
#define HTRACE_PROCESS_PARSER_H
#include <cstdint>
#include <map>
#include <string>
#include "htrace_plugin_time_parser.h"
#include "process_plugin_result.pb.h"
#include "trace_streamer_filters.h"
#include "cpu_plugin_result.pb.h"


namespace SysTuning {
namespace TraceStreamer {
class HtraceProcessParser : public HtracePluginTimeParser {
public:
    HtraceProcessParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx);
    ~HtraceProcessParser();
    void Parse(ProcessData& tracePacket, uint64_t ts);
    void Finish();
    struct TsLiveProcessData {
        void SetLiveProcess(uint64_t ts,
                            ProcessInfo& liveProcessInfo,
                            CpuInfo& cpuUsageData,
                            PssInfo& pssInfo,
                            DiskioInfo& diskio)
        {
            ts_ = ts;
            processInfo_ = std::make_unique<ProcessInfo>(liveProcessInfo);
            cpuUsageData_ = std::make_unique<CpuInfo>(cpuUsageData);
            pssInfo_ = std::make_unique<PssInfo>(pssInfo);
            diskio_ = std::make_unique<DiskioInfo>(diskio);
        }
        uint64_t ts_;
        std::unique_ptr<ProcessInfo> processInfo_;
        std::unique_ptr<CpuInfo> cpuUsageData_;
        std::unique_ptr<PssInfo> pssInfo_;
        std::unique_ptr<DiskioInfo> diskio_;
    };
    std::vector<std::unique_ptr<TsLiveProcessData>> liveProcessData_;
};
} // namespace TraceStreamer
} // namespace SysTuning

#endif // HTRACE_PROCESS_PARSER_H
