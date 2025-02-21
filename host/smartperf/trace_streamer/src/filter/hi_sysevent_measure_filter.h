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

#ifndef HI_SYS_EVENT_MEASURE_FILTER_H
#define HI_SYS_EVENT_MEASURE_FILTER_H

#include <map>
#include <string_view>
#include <tuple>

#include "double_map.h"
#include "filter_base.h"
#include "trace_data_cache.h"
#include "trace_streamer_filters.h"
#include "triple_map.h"

namespace SysTuning {
namespace TraceStreamer {
class HiSysEventMeasureFilter : private FilterBase {
public:
    HiSysEventMeasureFilter(TraceDataCache* dataCache, const TraceStreamerFilters* filter);
    HiSysEventMeasureFilter(const HiSysEventMeasureFilter&) = delete;
    HiSysEventMeasureFilter& operator=(const HiSysEventMeasureFilter&) = delete;
    ~HiSysEventMeasureFilter() override;
    DataIndex GetOrCreateFilterId(DataIndex eventSource);
    DataIndex GetOrCreateFilterId(DataIndex eventSource, DataIndex appName);
    std::tuple<DataIndex, DataIndex> GetOrCreateFilterId(DataIndex eventSource, DataIndex appName, DataIndex key);
    DataIndex AppendNewValue(uint64_t serial,
                             uint64_t timestamp,
                             DataIndex appNameId,
                             DataIndex key,
                             int32_t type,
                             double numericValue,
                             DataIndex strValue);
    void AppendNewValue(int32_t brightnessState,
                        int32_t btState,
                        int32_t locationState,
                        int32_t wifiState,
                        int32_t streamDefault,
                        int32_t voiceCall,
                        int32_t music,
                        int32_t streamRing,
                        int32_t media,
                        int32_t voiceAssistant,
                        int32_t system,
                        int32_t alarm,
                        int32_t notification,
                        int32_t bluetoolthSco,
                        int32_t enforcedAudible,
                        int32_t streamDtmf,
                        int32_t streamTts,
                        int32_t accessibility,
                        int32_t recording,
                        int32_t streamAll);
    void Clear();

private:
    DataIndex GetOrCreateFilterIdInternal(DataIndex appNameId, DataIndex key);
    DoubleMap<DataIndex, DataIndex, DataIndex> appKey_;
    DoubleMap<DataIndex, DataIndex, DataIndex> appName_;
    std::map<DataIndex, DataIndex> eventSource_;
};
} // namespace TraceStreamer
} // namespace SysTuning
#endif // HI_SYS_EVENT_MEASURE_FILTER_H
