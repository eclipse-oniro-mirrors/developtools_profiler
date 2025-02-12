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
#ifndef SRC_PRINT_EVENT_PARSER_H
#define SRC_PRINT_EVENT_PARSER_H
#include <regex>
#include <string_view>
#include "common_types.h"
#include "event_parser_base.h"
#include "filter/measure_filter.h"
#include "filter/process_filter.h"
#include "filter/slice_filter.h"
#include "string_to_numerical.h"
#include "trace_streamer_config.h"
namespace SysTuning {
namespace TraceStreamer {
class PrintEventParser : private EventParserBase {
public:
    PrintEventParser(TraceDataCache* dataCache, const TraceStreamerFilters* filter);
    bool ParsePrintEvent(const std::string& comm, uint64_t ts, uint32_t pid, std::string_view event);
private:
    ParseResult GetTracePoint(std::string_view pointStr, TracePoint& outPoint) const;
    ParseResult CheckTracePoint(std::string_view pointStr) const;
    uint32_t GetThreadGroupId(std::string_view pointStr, size_t& length) const;
    std::string_view GetPointNameForBegin(std::string_view pointStr, size_t tGidlength) const;
    ParseResult HandlerB(std::string_view pointStr, TracePoint& outPoint, size_t tGidlength) const;
    static ParseResult HandlerE(void);
    ParseResult HandlerCSF(std::string_view pointStr, TracePoint& outPoint, size_t tGidlength) const;
    static size_t GetNameLength(std::string_view pointStr, size_t nameIndex);
    size_t GetValueLength(std::string_view pointStr, size_t valueIndex) const;
private:
    const uint32_t pointLength_;
    const uint32_t maxPointLength_;
    TraceStreamerConfig config_{};
};
} // namespace TraceStreamer
} // namespace SysTuning

#endif // SRC_PRINT_EVENT_PARSER_H
