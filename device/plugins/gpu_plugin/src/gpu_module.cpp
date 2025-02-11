/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <mutex>
#include "gpu_data_plugin.h"

namespace {
constexpr uint32_t MAX_BUFFER_SIZE = 4 * 1024 * 1024;
std::unique_ptr<GpuDataPlugin> g_plugin = nullptr;
std::mutex g_taskMutex;
} // namespace

static int GpuDataPluginSessionStart(const uint8_t* configData, uint32_t configSize)
{
    std::lock_guard<std::mutex> guard(g_taskMutex);
    g_plugin = std::make_unique<GpuDataPlugin>();
    return g_plugin->Start(configData, configSize);
}

static int GpuPluginReportResult(uint8_t* bufferData, uint32_t bufferSize)
{
    std::lock_guard<std::mutex> guard(g_taskMutex);
    CHECK_NOTNULL(g_plugin, -1, "g_plugin is nullptr");
    return g_plugin->Report(bufferData, bufferSize);
}

static int GpuPluginReportResultOptimize(RandomWriteCtx* randomWrite)
{
    std::lock_guard<std::mutex> guard(g_taskMutex);
    return g_plugin->ReportOptimize(randomWrite);
}

static int GpuPluginSessionStop()
{
    std::lock_guard<std::mutex> guard(g_taskMutex);
    g_plugin->Stop();
    return 0;
}

static PluginModuleCallbacks g_callbacks = {
    .onPluginSessionStart = GpuDataPluginSessionStart,
    .onPluginReportResult = GpuPluginReportResult,
    .onPluginSessionStop = GpuPluginSessionStop,
    .onPluginReportResultOptimize = GpuPluginReportResultOptimize,
};

EXPORT_API PluginModuleStruct g_pluginModule = {
    .callbacks = &g_callbacks,
    .name = "gpu-plugin",
    .version = "1.02",
    .resultBufferSizeHint = MAX_BUFFER_SIZE,
};
