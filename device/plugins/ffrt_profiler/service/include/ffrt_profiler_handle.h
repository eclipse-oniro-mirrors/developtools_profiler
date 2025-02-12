/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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

#ifndef FFRT_PROFILER_HANDLE_H
#define FFRT_PROFILER_HANDLE_H

#include <chrono>
#include <variant>

#include "logging.h"

#include "buffer_writer.h"
#include "ffrt_profiler_result.pb.h"
#include "ffrt_profiler_result.pbencoder.h"
#include "ffrt_profiler_common.h"

using WriterStructPtr = std::unique_ptr<WriterStruct>::pointer;
namespace OHOS::Developtools::Profiler {
class FfrtProfilerManager;

class FfrtProfilerHandle {
public:
    explicit FfrtProfilerHandle(uint32_t bufferSize, bool isProtobufSerialize = true);
    ~FfrtProfilerHandle();

    void SetWriter(const std::shared_ptr<Writer>& writer);
    void SetWriter(const WriterStructPtr& writer);
    void SerializeData(const int8_t data[], uint32_t size);
    void SetTargetProcessInfo(uint32_t pid, const std::string& name)
    {
        pid_ = pid;
        processName_ = name;
    }

private:
    template <typename T>
    void FlushCheck(T& protoData);
    void FlushData(::FfrtProfilerResult& data);
    void FlushData(ProtoEncoder::FfrtProfilerResult& data);
    template <typename T>
    void SerializeDataImpl(T& protoData, const int8_t data[], uint32_t size);
    template <typename T>
    void SerializeBaseData(T& baseDataProto, const int8_t* data);
    template <typename T>
    void SerializeTraceData(T& protoData, const int8_t data[], uint32_t size);
    template <typename T>
    void ReportCommonData(T& protoData, FfrtResultBase* base);
    template <typename T>
    void SerializeRawData(T& protoData, const int8_t data[], uint32_t size);

private:
    std::unique_ptr<uint8_t[]> buffer_{nullptr};
    std::shared_ptr<Writer> writer_{nullptr};
    WriterStructPtr writerStruct_{nullptr};
    bool isProtobufSerialize_{true};
    std::variant<::FfrtProfilerResult, ProtoEncoder::FfrtProfilerResult> protoData_;
    uint32_t flushCount_{0};
    uint32_t bufferSize_{0};
    uint32_t pid_{0};
    std::string processName_;
    bool reportProcessName_{true};
};
} // OHOS::Developtools::Profiler

#endif // FFRT_PROFILER_HANDLE_H