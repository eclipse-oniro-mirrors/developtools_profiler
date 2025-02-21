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
#ifndef HTRACE_NATIVE_HOOK_PARSER_H
#define HTRACE_NATIVE_HOOK_PARSER_H
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include "double_map.h"
#include "htrace_event_parser.h"
#include "htrace_plugin_time_parser.h"
#include "native_hook_result.pb.h"
#include "quatra_map.h"
#include "trace_streamer_config.h"
#include "trace_streamer_filters.h"

namespace SysTuning {
namespace TraceStreamer {
class HtraceNativeHookParser : public HtracePluginTimeParser {
public:
    HtraceNativeHookParser(TraceDataCache* dataCache, const TraceStreamerFilters* ctx);
    ~HtraceNativeHookParser();
    void SortNativeHookData(BatchNativeHookData& tracePacket);
    void FinishParseNativeHookData();
    void Finish();

private:
    class NativeHookFrameTemp {
    public:
        NativeHookFrameTemp() {}
        NativeHookFrameTemp(uint64_t fileId, uint64_t symbolId, uint32_t depth, uint64_t offset, uint64_t symbolOffset)
            : fileId_(fileId), symbolId_(symbolId), depth_(depth), offset_(offset), symbolOffset_(symbolOffset)
        {
        }
        ~NativeHookFrameTemp() {}
        uint64_t fileId_ = 0;
        uint64_t symbolId_ = 0;
        uint32_t depth_ = 0;
        uint32_t ip_ = 0;
        uint32_t sp_ = 0;
        uint64_t offset_ = 0;
        uint64_t symbolOffset_ = 0;
    };
    template <class T1, class T2>
    void UpdateMap(std::unordered_map<T1, T2>& sourceMap, T1 key, T2 value);
    void MaybeParseNativeHookData();
    void ParseNativeHookData(const uint64_t timeStamp, const NativeHookData* nativeHookData);
    uint64_t ParseNativeHookFrame(const RepeatedPtrField<::Frame>& repeatedFrame);
    void MaybeUpdateCurrentSizeDur(uint64_t row, uint64_t timeStamp, bool isMalloc);
    void UpdateThreadNameWithNativeHookData() const;
    void ParseAllocEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData);
    void ParseFreeEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData);
    void ParseMmapEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData);
    void ParseMunmapEvent(uint64_t newTimeStamp, const NativeHookData* nativeHookData);
    void ParseTagEvent(const NativeHookData* nativeHookData);
    void ParseFileEvent(const NativeHookData* nativeHookData);
    void ParseSymbolEvent(const NativeHookData* nativeHookData);
    void ParseThreadEvent(const NativeHookData* nativeHookData);
    uint64_t callChainId_ = 0;
    DoubleMap<uint32_t, uint64_t, uint64_t> addrToAllocEventRow_;
    DoubleMap<uint32_t, uint64_t, uint64_t> addrToMmapEventRow_;
    uint64_t lastMallocEventRaw_ = INVALID_UINT64;
    uint64_t lastMmapEventRaw_ = INVALID_UINT64;
    std::multimap<uint64_t, std::unique_ptr<NativeHookData>> tsNativeHookQueue_ = {};
    std::unordered_map<uint32_t, uint64_t> threadNameIdToThreadName_ = {};
    std::unordered_map<uint32_t, uint32_t> itidToThreadNameId_ = {};
    QuatraMap<uint64_t, uint64_t, uint64_t, uint64_t, uint64_t> frameToFrameId_;
    std::set<DataIndex> invalidLibPathIndexs_ = {};
    std::map<uint32_t, uint64_t> filePathIdToFilePathName_ = {};
    const size_t MAX_CACHE_SIZE = 200000;
};
} // namespace TraceStreamer
} // namespace SysTuning

#endif // HTRACE_NATIVE_HOOK_PARSER_H
