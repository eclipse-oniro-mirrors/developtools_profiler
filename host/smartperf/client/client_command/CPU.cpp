/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "include/CPU.h"
#include <sstream>
#include <cstdio>
#include <unistd.h>
#include <cstring>
#include <string>
#include <iostream>
#include <climits>
#include "securec.h"
#include "include/sp_utils.h"
#include "cpu_collector.h"
#include "collect_result.h"
#include "include/startup_delay.h"
#include "include/sp_log.h"

using namespace OHOS::HiviewDFX;
using namespace OHOS::HiviewDFX::UCollectUtil;
using namespace OHOS::HiviewDFX::UCollect;

namespace OHOS {
namespace SmartPerf {
std::map<std::string, std::string> CPU::ItemData()
{
    std::map<std::string, std::string> result;
    std::vector<CpuFreqs> cpuFreqInfo = GetCpuFreq();
    for (size_t i = 0; i < cpuFreqInfo.size(); i++) {
        std::string cpuFreqStr = std::to_string(cpuFreqInfo[i].curFreq);
        std::string cpuId = std::to_string(cpuFreqInfo[i].cpuId);
        result["cpu" + cpuId + "Frequency"] = cpuFreqStr;
    }
    std::vector<CpuUsageInfos> workLoads = GetCpuUsage();
    const size_t oneHundred = 100;
    if (workLoads.empty()) {
        return result;
    }
    for (size_t i = 1; i < workLoads.size(); i++) {
        std::string cpuIdStr = workLoads[i].cpuId;
        std::string userUsageStr = std::to_string(workLoads[i].userUsage * oneHundred);
        std::string niceUsageStr = std::to_string(workLoads[i].niceUsage * oneHundred);
        std::string systemUsageStr = std::to_string(workLoads[i].systemUsage * oneHundred);
        std::string idleUsageStr = std::to_string(workLoads[i].idleUsage * oneHundred);
        std::string ioWaitUsageStr = std::to_string(workLoads[i].ioWaitUsage * oneHundred);
        std::string irqUsageStr = std::to_string(workLoads[i].irqUsage * oneHundred);
        std::string softIrqUsageStr = std::to_string(workLoads[i].softIrqUsage * oneHundred);
        std::string totalUsageStr = std::to_string((workLoads[i].userUsage + workLoads[i].niceUsage +
            workLoads[i].systemUsage + workLoads[i].ioWaitUsage + workLoads[i].irqUsage + workLoads[i].softIrqUsage) *
            oneHundred);
        result[cpuIdStr + "userUsage"] = userUsageStr;
        result[cpuIdStr + "niceUsage"] = niceUsageStr;
        result[cpuIdStr + "systemUsage"] = systemUsageStr;
        result[cpuIdStr + "idleUsage"] = idleUsageStr;
        result[cpuIdStr + "ioWaitUsage"] = ioWaitUsageStr;
        result[cpuIdStr + "irqUsage"] = irqUsageStr;
        result[cpuIdStr + "softIrqUsage"] = softIrqUsageStr;
        result[cpuIdStr + "Usage"] = totalUsageStr;
    }
    if (packageName.length() > 0) {
        std::map<std::string, std::string> processCpuInfo = CPU::GetSysProcessCpuLoad();
        if (!processCpuInfo.empty()) {
            for (auto it = processCpuInfo.begin(); it != processCpuInfo.end(); ++it) {
                result.insert(*it);
            }
        }
    }

    LOGI("CPU::ItemData map size(%u)", result.size());
    return result;
}

void CPU::SetPackageName(const std::string &pName)
{
    packageName = pName;
    LOGI("CPU SetPackageName name(%s)", pName.c_str());
}

std::vector<CpuFreqs> CPU::GetCpuFreq()
{
    OHOS::SmartPerf::CpuFreqs cpuFreqs;
    std::vector<CpuFreqs> cpuFrequency;
    std::shared_ptr<CpuCollector> collector = CpuCollector::Create();
    CollectResult<std::vector<CpuFreq>> result = collector->CollectCpuFrequency();
    std::vector<CpuFreq> &cpufreq = result.data;
    for (size_t i = 0; i < cpufreq.size(); i++) {
        cpuFreqs.cpuId = cpufreq[i].cpuId;
        cpuFreqs.curFreq = cpufreq[i].curFreq;
        cpuFrequency.push_back(cpuFreqs);
        LOGI("cpuFreqs.cpuId: %s", std::to_string(cpufreq[i].cpuId).c_str());
        LOGI("cpuFreqs.curFreq: %s", std::to_string(cpufreq[i].curFreq).c_str());
    }
    return cpuFrequency;
}

std::vector<CpuUsageInfos> CPU::GetCpuUsage()
{
    OHOS::SmartPerf::CpuUsageInfos cpuUsageInfos;
    std::vector<CpuUsageInfos> workload;
    std::shared_ptr<CpuCollector> collector = CpuCollector::Create();
    CollectResult<SysCpuUsage> result = collector->CollectSysCpuUsage(true);
    SysCpuUsage &sysCpuUsage = result.data;
    if (sysCpuUsage.cpuInfos.empty()) {
        return workload;
    }
    for (auto &cpuInfo : sysCpuUsage.cpuInfos) {
        cpuUsageInfos.cpuId = cpuInfo.cpuId;
        cpuUsageInfos.userUsage = cpuInfo.userUsage;
        cpuUsageInfos.niceUsage = cpuInfo.niceUsage;
        cpuUsageInfos.systemUsage = cpuInfo.systemUsage;
        cpuUsageInfos.idleUsage = cpuInfo.idleUsage;
        cpuUsageInfos.ioWaitUsage = cpuInfo.ioWaitUsage;
        cpuUsageInfos.irqUsage = cpuInfo.irqUsage;
        cpuUsageInfos.softIrqUsage = cpuInfo.softIrqUsage;
        workload.push_back(cpuUsageInfos);
        LOGI("UsageCpuId: %s", cpuInfo.cpuId.c_str());
        LOGI("userUsage: %s", std::to_string(cpuInfo.userUsage).c_str());
        LOGI("niceUsage: %s", std::to_string(cpuInfo.niceUsage).c_str());
        LOGI("systemUsage: %s", std::to_string(cpuInfo.systemUsage).c_str());
        LOGI("idleUsage: %s", std::to_string(cpuInfo.idleUsage).c_str());
        LOGI("ioWaitUsage: %s", std::to_string(cpuInfo.ioWaitUsage).c_str());
        LOGI("irqUsage: %s", std::to_string(cpuInfo.irqUsage).c_str());
        LOGI("softIrqUsage: %s", std::to_string(cpuInfo.softIrqUsage).c_str());
    }
    return workload;
}

std::map<std::string, std::string> CPU::GetSysProcessCpuLoad() const
{
    std::string processId = "";
    OHOS::SmartPerf::StartUpDelay sp;
    processId = sp.GetPidByPkg(packageName);
    LOGI("CPU::processId -- %s", processId.c_str());
    std::map<std::string, std::string> processCpuInfo;
    const size_t oneHundred = 100;
    if (processId.length() > 0) {
        int32_t procId = 0;
        procId = std::stoi(processId);
        std::shared_ptr<CpuCollector> collector = CpuCollector::Create();
        auto collectResult = collector->CollectProcessCpuStatInfo(procId, true);
        auto data = collectResult.data;
        processCpuInfo["ProcId"] = std::to_string(data.pid);
        processCpuInfo["ProcAppName"] = data.procName;
        processCpuInfo["ProcCpuLoad"] = std::to_string(data.cpuLoad * oneHundred);
        processCpuInfo["ProcCpuUsage"] = std::to_string(data.cpuUsage * oneHundred);
        processCpuInfo["ProcUCpuUsage"] = std::to_string(data.uCpuUsage * oneHundred);
        processCpuInfo["ProcSCpuUsage"] = std::to_string(data.sCpuUsage * oneHundred);
        LOGI("ProcId: %s", std::to_string(data.pid).c_str());
        LOGI("ProcAppName: %s", data.procName.c_str());
        LOGI("ProcCpuLoad: %s", std::to_string(data.cpuLoad).c_str());
        LOGI("ProcCpuUsage: %s", std::to_string(data.cpuUsage).c_str());
        LOGI("ProcUCpuUsage: %s", std::to_string(data.uCpuUsage).c_str());
        LOGI("ProcSCpuUsage: %s", std::to_string(data.sCpuUsage).c_str());
    } else {
        processCpuInfo["ProcId"] = "NA";
        processCpuInfo["ProcAppName"] = packageName;
        processCpuInfo["ProcCpuLoad"] = "NA";
        processCpuInfo["ProcCpuUsage"] = "NA";
        processCpuInfo["ProcUCpuUsage"] = "NA";
        processCpuInfo["ProcSCpuUsage"] = "NA";
    }
    if (processCpuInfo.find("ProcAppName") != processCpuInfo.end() && processCpuInfo["ProcAppName"].empty()) {
        processCpuInfo["ProcId"] = "NA";
        processCpuInfo["ProcAppName"] = packageName;
        processCpuInfo["ProcCpuLoad"] = "NA";
        processCpuInfo["ProcCpuUsage"] = "NA";
        processCpuInfo["ProcUCpuUsage"] = "NA";
        processCpuInfo["ProcSCpuUsage"] = "NA";
    }
    return processCpuInfo;
}
}
}
