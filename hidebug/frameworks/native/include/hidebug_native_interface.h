/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HIVIEWDFX_HIDEBUG_NATIVE_INTERFACE_H
#define HIVIEWDFX_HIDEBUG_NATIVE_INTERFACE_H

#include <map>
#include <memory>
#include <optional>
#include "hitrace_meter.h"
#include "resource/memory.h"
#include "hidebug/hidebug_type.h"

namespace OHOS {
namespace HiviewDFX {
enum MemoryState {
    MEMORY_FAILED = -1,
    MEMORY_SUCCESS = 0,
};

class HidebugNativeInterface {
public:
    static std::unique_ptr<HidebugNativeInterface> CreateInstance();
    virtual ~HidebugNativeInterface() = default;

    /**
     * GetSystemCpuUsage
     *
     * @return the cpu usage of the system
     */
    virtual std::optional<double> GetSystemCpuUsage() = 0;

    virtual double GetCpuUsage() = 0;
    virtual std::map<uint32_t, double> GetAppThreadCpuUsage() = 0;
    virtual HiDebug_ErrorCode StartAppTraceCapture(uint64_t tags, uint32_t flag,
        uint32_t limitsize, std::string &file) = 0;
    virtual HiDebug_ErrorCode StopAppTraceCapture() = 0;
    virtual int GetMemoryLeakResource(const std::string& type, int32_t value, bool enabledDebugLog) = 0;
    virtual std::optional<MemoryLimit> GetAppMemoryLimit() = 0;
    virtual std::optional<HiDebug_NativeMemInfo> GetAppNativeMemInfo() = 0;
    virtual std::optional<SysMemory> GetSystemMemInfo() = 0;
    virtual bool IsDebuggerConnected() = 0;
};
}
}

#endif  // HIVIEWDFX_HIDEBUG_NATIVE_INTERFACE_H
