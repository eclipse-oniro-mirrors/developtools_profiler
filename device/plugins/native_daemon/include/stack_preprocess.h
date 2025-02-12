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
#ifndef STACK_PREPROCESS_H
#define STACK_PREPROCESS_H

#include <chrono>
#include <thread>
#include <unordered_map>

#include "logging.h"
#include "nocopyable.h"
#include "stack_data_repeater.h"
#include "buffer_writer.h"
#include "virtual_runtime.h"
#include "hook_common.h"
#include "native_hook_config.pb.h"
#include "native_hook_result.pb.h"

class StackPreprocess {
public:
    explicit StackPreprocess(const StackDataRepeaterPtr& dataRepeater, NativeHookConfig hookConfig);

    ~StackPreprocess();
    void SetWriter(const std::shared_ptr<BufferWriter>& writer);
    bool StartTakeResults();
    bool StopTakeResults();

private:
    void TakeResults();
    void SetHookData(RawStackPtr RawStack, std::vector<OHOS::Developtools::NativeDaemon::CallFrame>& callsFrames,
        BatchNativeHookData& batchNativeHookData);
    void writeFrames(RawStackPtr RawStack, const std::vector<OHOS::Developtools::NativeDaemon::CallFrame>& callsFrames);
    void SetFrameInfo(Frame& frame, OHOS::Developtools::NativeDaemon::CallFrame& callsFrame,
        BatchNativeHookData& batchNativeHookData);
    uint32_t GetThreadIdx(std::string threadName, BatchNativeHookData& batchNativeHookData);
private:
    std::shared_ptr<BufferWriter> writer_ = nullptr;
    StackDataRepeaterPtr dataRepeater_ = nullptr;
    std::thread thread_ {};
    std::unique_ptr<uint8_t[]> buffer_;
    bool isStopTakeData_ = false;
    std::shared_ptr<OHOS::Developtools::NativeDaemon::VirtualRuntime> runtime_instance;
    DISALLOW_COPY_AND_MOVE(StackPreprocess);
    std::unordered_map<std::string, uint32_t> functionMap_;
    std::unordered_map<std::string, uint32_t> fileMap_;
    std::unordered_map<std::string, uint32_t> threadMap_;
    NativeHookConfig hookConfig_;
    std::unique_ptr<FILE, decltype(&fclose)> fpHookData_;
    uint32_t ignoreCnts_ = 0;
    uint32_t eventCnts_ = 0;
};

#endif // STACK_PREPROCESS_H