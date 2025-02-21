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
#ifndef RESULT_DEMUXER_H
#define RESULT_DEMUXER_H

#include <chrono>
#include <thread>

#include "logging.h"
#include "nocopyable.h"
#include "plugin_session_manager.h"
#include "profiler_data_repeater.h"
#include "profiler_service.grpc.pb.h"
#include "trace_file_writer.h"

using PluginSessionManagerPtr = STD_PTR(shared, PluginSessionManager);

class ResultDemuxer {
public:
    explicit ResultDemuxer(const ProfilerDataRepeaterPtr& dataRepeater, PluginSessionManagerPtr pluginSessionManager);

    ~ResultDemuxer();

    void SetTraceWriter(const TraceFileWriterPtr& traceWriter);

    void SetFlushInterval(std::chrono::milliseconds interval);

    bool StartTakeResults();

    bool StopTakeResults();

private:
    void TakeResults();

private:
    TraceFileWriterPtr traceWriter_ = nullptr;
    ProfilerDataRepeaterPtr dataRepeater_ = nullptr;
    std::chrono::milliseconds flushInterval_ {};
    std::chrono::steady_clock::time_point lastFlushTime_ {};
    std::thread demuxerThread_ {};
    bool isStopTakeData_ = false;
    PluginSessionManagerPtr pluginSessionManager_ = nullptr;

    DISALLOW_COPY_AND_MOVE(ResultDemuxer);
};

#endif // RESULT_DEMUXER_H