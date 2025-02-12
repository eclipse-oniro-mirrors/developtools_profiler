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
#ifndef EBPF_DATA_PARSER_H
#define EBPF_DATA_PARSER_H
#include "bio_latency_data_parser.h"
#include "ebpf_data_reader.h"
#include "ebpf_stdtype.h"
#include "file_system_data_parser.h"
#include "paged_memory_data_parser.h"
#include "trace_data/trace_data_cache.h"
#include "trace_streamer_filters.h"

namespace SysTuning {
namespace TraceStreamer {
class EbpfDataParser : public FileSystemDataParser, public PagedMemoryDataParser, public BioLatencyDataParser {
public:
    EbpfDataParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx);
    ~EbpfDataParser();
    void InitAndParseEbpfData(const std::deque<uint8_t>& dequeBuffer, uint64_t size);
    void Finish();

private:
    bool Init(const std::deque<uint8_t>& dequeBuffer, uint64_t size);
    std::unique_ptr<EbpfDataReader> reader_;
    uint64_t ebpfAllEventStartTime_ = std::numeric_limits<uint64_t>::max();
    uint64_t ebpfAllEventEndTime_ = 0;
};
} // namespace TraceStreamer
} // namespace SysTuning
#endif // EBPF_DATA_PARSER_H
