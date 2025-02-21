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
#include "result_demuxer.h"

#include <unistd.h>

#include "logging.h"
#include "trace_file_header.h"

namespace {
constexpr auto DEFAULT_FLUSH_INTERVAL = std::chrono::milliseconds(1000);
} // namespace

ResultDemuxer::ResultDemuxer(const ProfilerDataRepeaterPtr& dataRepeater, PluginSessionManagerPtr pluginSessionManager)
    : dataRepeater_(dataRepeater), flushInterval_(DEFAULT_FLUSH_INTERVAL)
{
    pluginSessionManager_ = pluginSessionManager;
}

ResultDemuxer::~ResultDemuxer()
{
    isStopTakeData_ = true;
    if (dataRepeater_) {
        dataRepeater_->Close();
    }
    if (demuxerThread_.joinable()) {
        demuxerThread_.join();
    }
}

void ResultDemuxer::SetTraceWriter(const TraceFileWriterPtr& traceWriter)
{
    traceWriter_ = traceWriter;
}

void ResultDemuxer::SetFlushInterval(std::chrono::milliseconds interval)
{
    flushInterval_ = interval;
}

bool ResultDemuxer::StartTakeResults()
{
    CHECK_NOTNULL(dataRepeater_, false, "data repeater null");

    std::thread demuxer(&ResultDemuxer::TakeResults, this);
    CHECK_TRUE(demuxer.get_id() != std::thread::id(), false, "thread invalid");

    demuxerThread_ = std::move(demuxer);
    isStopTakeData_ = false;
    return true;
}

bool ResultDemuxer::StopTakeResults()
{
    CHECK_NOTNULL(dataRepeater_, false, "data repeater null");
    CHECK_TRUE(demuxerThread_.get_id() != std::thread::id(), false, "thread invalid");

    isStopTakeData_ = true;
    dataRepeater_->PutPluginData(nullptr);
    if (demuxerThread_.joinable()) {
        demuxerThread_.join();
    }
    return true;
}

void ResultDemuxer::TakeResults()
{
    if (!dataRepeater_ || !pluginSessionManager_) {
        return;
    }

    HILOG_INFO(LOG_CORE, "TakeResults thread %d, start!", gettid());
    lastFlushTime_ = std::chrono::steady_clock::now();
    while (1) {
        auto pluginData = dataRepeater_->TakePluginData();
        if (!pluginData || isStopTakeData_) {
            break;
        }

        if (traceWriter_) {
            int ret = traceWriter_->Write(*pluginData);
            if (ret == -1) {
                HILOG_DEBUG(LOG_CORE, "need to clear queue and report the basic data");
                dataRepeater_->ClearQueue();
                pluginSessionManager_->RefreshPluginSession();
            }
            auto currentTime = std::chrono::steady_clock::now();
            auto elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - lastFlushTime_);
            if (elapsedTime >= flushInterval_) {
                traceWriter_->Flush();
                lastFlushTime_ = currentTime;
            }
        } else {
            HILOG_WARN(LOG_CORE, "no writer, drop data!");
        }
    }
    traceWriter_->Finish();
    HILOG_INFO(LOG_CORE, "TakeResults thread %d, exit!", gettid());
}
