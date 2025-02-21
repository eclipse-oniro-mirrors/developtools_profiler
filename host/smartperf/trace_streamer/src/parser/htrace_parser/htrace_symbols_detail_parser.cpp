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
#include "htrace_symbols_detail_parser.h"
#include "htrace_event_parser.h"
#include "symbols_filter.h"
namespace SysTuning {
namespace TraceStreamer {
HtraceSymbolsDetailParser::HtraceSymbolsDetailParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx)
    : streamFilters_(ctx), traceDataCache_(dataCache)
{
    UNUSED(traceDataCache_);
    if (!streamFilters_) {
        TS_LOGF("streamFilters_ should not be null");
        return;
    }
}

HtraceSymbolsDetailParser::~HtraceSymbolsDetailParser() = default;
void HtraceSymbolsDetailParser::Parse(const TracePluginResult* tracePacket)
{
    if (!tracePacket->symbols_detail_size()) {
        return;
    }
    for (int i = 0; i < tracePacket->symbols_detail_size(); i++) {
        auto symbol = const_cast<TracePluginResult*>(tracePacket)->mutable_symbols_detail(i);
        TS_LOGD("symbol_name:%s, symbol_addr:%lu", symbol->symbol_name().c_str(), symbol->symbol_addr());
        // symbol
        streamFilters_->symbolsFilter_->RegisterFunc(symbol->symbol_addr(),
                                                     traceDataCache_->GetDataIndex(symbol->symbol_name()));
    }
}
} // namespace TraceStreamer
} // namespace SysTuning
