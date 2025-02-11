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

#include "native_memory_profiler_sa_client_manager.h"

#include "native_memory_profiler_sa_proxy.h"

#include "logging.h"

namespace OHOS::Developtools::NativeDaemon {
namespace {
constexpr uint32_t LIB_SMS = 4096;
constexpr uint32_t CALL_STACK_SMS = 16384;
}

int32_t NativeMemoryProfilerSaClientManager::Start(std::shared_ptr<NativeMemoryProfilerSaConfig>& config)
{
    CHECK_NOTNULL(config, RET_ERR, "NativeMemoryProfilerSaClientManager: config is nullptr");
    CHECK_TRUE(CheckConfig(config), RET_ERR, "CheckConfig failed");
    auto service = GetRemoteService();
    if (service == nullptr) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: start GetRemoteService failed");
        return RET_ERR;
    }
    NativeMemoryProfilerSaProxy proxy(service);
    return proxy.Start(config);
}

int32_t NativeMemoryProfilerSaClientManager::Start(NativeMemProfilerType type, uint32_t pid, uint32_t duration,
    uint32_t sampleIntervel)
{
    if (pid == 0) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: pid cannot be 0");
        return RET_ERR;
    }
    auto config = std::make_shared<NativeMemoryProfilerSaConfig>();
    CHECK_NOTNULL(config, RET_ERR, "NativeMemoryProfilerSaClientManager: config is nullptr");
    config->pid_ = static_cast<int32_t>(pid);
    config->duration_ = duration;
    config->sampleInterval_ = sampleIntervel;
    if (type == NativeMemProfilerType::MEM_PROFILER_LIBRARY) {
        config->responseLibraryMode_ = true;
    } else if (type == NativeMemProfilerType::MEM_PROFILER_CALL_STACK) {
        config->responseLibraryMode_ = false;
    }
    return Start(config);
}

int32_t NativeMemoryProfilerSaClientManager::Stop(uint32_t pid)
{
    CHECK_TRUE(pid != 0, RET_ERR, "NativeMemoryProfilerSaClientManager: pid is 0");
    auto service = GetRemoteService();
    if (service == nullptr) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: stop GetRemoteService failed");
        return RET_ERR;
    }
    NativeMemoryProfilerSaProxy proxy(service);
    return proxy.Stop(pid);
}

int32_t NativeMemoryProfilerSaClientManager::Stop(const std::string& name)
{
    CHECK_TRUE(!name.empty(), RET_ERR, "NativeMemoryProfilerSaClientManager: name is empty");
    auto service = GetRemoteService();
    if (service == nullptr) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: stop GetRemoteService failed");
        return RET_ERR;
    }
    NativeMemoryProfilerSaProxy proxy(service);
    return proxy.Stop(name);
}

int32_t NativeMemoryProfilerSaClientManager::DumpData(uint32_t fd,
                                                      std::shared_ptr<NativeMemoryProfilerSaConfig>& config)
{
    CHECK_TRUE(fd != 0, RET_ERR, "NativeMemoryProfilerSaClientManager: fd is 0");
    CHECK_NOTNULL(config, RET_ERR, "NativeMemoryProfilerSaClientManager: config is nullptr");
    CHECK_TRUE(CheckConfig(config), RET_ERR, "CheckConfig failed");
    auto service = GetRemoteService();
    if (service == nullptr) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: stop GetRemoteService failed");
        return RET_ERR;
    }
    NativeMemoryProfilerSaProxy proxy(service);
    return proxy.DumpData(fd, config);
}

sptr<IRemoteObject> NativeMemoryProfilerSaClientManager::GetRemoteService()
{
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        return nullptr;
    }
    return abilityManager->CheckSystemAbility(INativeMemoryProfilerSa::NATIVE_DAEMON_SYSTEM_ABILITY_ID);
}

bool NativeMemoryProfilerSaClientManager::CheckConfig(const std::shared_ptr<NativeMemoryProfilerSaConfig>& config)
{
    CHECK_NOTNULL(config, false, "NativeMemoryProfilerSaClientManager: config is nullptr");
    if (config->duration_ == 0) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: duration cannot be 0");
        return false;
    }
    if (config->shareMemorySize_ == 0) {
        config->shareMemorySize_ = config->responseLibraryMode_ ? LIB_SMS : CALL_STACK_SMS;
    }
    return true;
}

int32_t NativeMemoryProfilerSaClientManager::GetMallocStats(int fd, int pid, int type)
{
    CHECK_TRUE(fd != 0, RET_ERR, "NativeMemoryProfilerSaClientManager: GetMallocStats fd is 0");
    CHECK_TRUE(pid > 0, RET_ERR, "NativeMemoryProfilerSaClientManager: GetMallocStats invalid pid");
    CHECK_TRUE(type == 0 || type == 1, RET_ERR, "NativeMemoryProfilerSaClientManager: type is invalid");
    std::shared_ptr<NativeMemoryProfilerSaConfig> config = std::make_shared<NativeMemoryProfilerSaConfig>();
    config->printNmd_ = true;
    config->nmdPid_ = static_cast<uint32_t>(pid);
    config->nmdType_ = static_cast<uint32_t>(type);
    auto service = GetRemoteService();
    if (service == nullptr) {
        PROFILER_LOG_ERROR(LOG_CORE, "NativeMemoryProfilerSaClientManager: stop GetRemoteService failed");
        return RET_ERR;
    }
    NativeMemoryProfilerSaProxy proxy(service);
    return proxy.DumpData(fd, config);
}
} // namespace OHOS::Developtools::NativeDaemon