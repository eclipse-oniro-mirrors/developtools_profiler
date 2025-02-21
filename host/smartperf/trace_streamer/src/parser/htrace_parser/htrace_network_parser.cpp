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
#include "htrace_network_parser.h"
#include "clock_filter.h"
#include "htrace_event_parser.h"
#include "process_filter.h"
#include "stat_filter.h"
namespace SysTuning {
namespace TraceStreamer {
HtraceNetworkParser::HtraceNetworkParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx)
    : HtracePluginTimeParser(dataCache, ctx)
{
}

HtraceNetworkParser::~HtraceNetworkParser()
{
    TS_LOGI("network ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(GetPluginStartTime()),
            static_cast<unsigned long long>(GetPluginEndTime()));
}

void HtraceNetworkParser::Parse(NetworkDatas& tracePacket, uint64_t ts)
{
    auto netSysInfo = tracePacket.network_system_info();
    ts = streamFilters_->clockFilter_->ToPrimaryTraceTime(TS_CLOCK_REALTIME, ts);
    streamFilters_->statFilter_->IncreaseStat(TRACE_NETWORK, STAT_EVENT_RECEIVED);
    networkData_.push_back(std::move(TsNetworkData{ts, netSysInfo}));
}
void HtraceNetworkParser::Finish()
{
    auto cmp = [](const TsNetworkData& a, const TsNetworkData& b) { return a.ts < b.ts; };
    std::sort(networkData_.begin(), networkData_.end(), cmp);
    bool firstTime = true;
    uint64_t lastTs = 0;
    uint64_t lastRx = 0;
    uint64_t lastTx = 0;
    uint64_t lastPacketIn = 0.0;
    uint64_t lastPacketOut = 0.0;
    for (auto itor = networkData_.begin(); itor != networkData_.end(); itor++) {
        auto networkSysData = itor->networkSysData;
        auto newTimeStamp = itor->ts;
        UpdatePluginTimeRange(TS_CLOCK_REALTIME, itor->ts, newTimeStamp);
        if (firstTime) {
            lastTs = newTimeStamp;
            lastRx = networkSysData.rx_bytes();
            lastTx = networkSysData.tx_bytes();
            lastPacketIn = networkSysData.rx_packets();
            lastPacketOut = networkSysData.tx_packets();
            firstTime = false;
            continue;
        }
        auto dur = newTimeStamp - lastTs;
        auto durS = 1.0 * dur / SEC_TO_NS;
        traceDataCache_->GetNetworkData()->AppendNewNetData(
            newTimeStamp, networkSysData.tx_bytes(), networkSysData.rx_bytes(), dur,
            1.0 * (networkSysData.rx_bytes() - lastRx) / durS, 1.0 * (networkSysData.tx_bytes() - lastTx) / durS,
            networkSysData.rx_packets(), 1.0 * (networkSysData.rx_packets() - lastPacketIn) / durS,
            networkSysData.tx_packets(), 1.0 * (networkSysData.tx_packets() - lastPacketOut) / durS, "undefined");
        lastTs = newTimeStamp;
        lastRx = networkSysData.rx_bytes();
        lastTx = networkSysData.tx_bytes();
        lastPacketIn = networkSysData.rx_packets();
        lastPacketOut = networkSysData.tx_packets();
    }
    networkData_.clear();
    traceDataCache_->MixTraceTime(GetPluginStartTime(), GetPluginEndTime());
}
} // namespace TraceStreamer
} // namespace SysTuning
