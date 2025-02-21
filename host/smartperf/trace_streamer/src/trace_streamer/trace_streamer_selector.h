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

#ifndef TRACE_STREAMER_SELECTOR_H
#define TRACE_STREAMER_SELECTOR_H
#include <functional>
#include <memory>
#include "trace_data/trace_data_cache.h"
#include "trace_streamer_filters.h"

namespace SysTuning {
namespace TraceStreamer {
class BytraceParser;
class HtraceParser;
enum TraceFileType { TRACE_FILETYPE_BY_TRACE, TRACE_FILETYPE_H_TRACE, TRACE_FILETYPE_SYSEVENT, TRACE_FILETYPE_UN_KNOW };
class TraceStreamerSelector {
public:
    TraceStreamerSelector();
    ~TraceStreamerSelector();
    bool ParseTraceDataSegment(std::unique_ptr<uint8_t[]> data, size_t size);
    void EnableMetaTable(bool enabled);
    static void SetCleanMode(bool cleanMode);
    int ExportDatabase(const std::string& outputName) const;
    int SearchData();
    int OperateDatabase(const std::string& sql);
    int SearchDatabase(const std::string& sql, TraceDataDB::ResultCallBack resultCallBack);
    int SearchDatabase(const std::string& sql, uint8_t* out, int outLen);
    int UpdateTraceRangeTime(uint8_t* data, int len);
    void WaitForParserEnd();
    void Clear();
    MetaData* GetMetaData();
    void SetDataType(TraceFileType type);
    void SetCancel(bool cancel);
    TraceFileType DataType() const
    {
        return fileType_;
    }

private:
    void InitFilter();
    TraceFileType fileType_;
    std::unique_ptr<TraceStreamerFilters> streamFilters_ = {};
    std::unique_ptr<TraceDataCache> traceDataCache_ = {};

    std::unique_ptr<BytraceParser> bytraceParser_;
    std::unique_ptr<HtraceParser> htraceParser_;
};
} // namespace TraceStreamer
} // namespace SysTuning

#endif // TRACE_STREAMER_SELECTOR_H
