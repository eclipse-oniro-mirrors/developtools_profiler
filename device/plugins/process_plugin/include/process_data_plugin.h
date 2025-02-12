/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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

#ifndef PROCESS_DATA_PLUGIN_H
#define PROCESS_DATA_PLUGIN_H

#include <algorithm>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <iomanip>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

#include "logging.h"
#include "process_plugin_config.pb.h"
#include "process_plugin_result.pb.h"
#include "plugin_module_api.h"

enum ErrorType {
    RET_NULL_ADDR,
    RET_IVALID_PID,
    RET_TGID_VALUE_NULL,
    RET_FAIL = -1,
    RET_SUCC = 0,
};

class ProcessDataPlugin {
public:
    ProcessDataPlugin();
    ~ProcessDataPlugin();
    int Start(const uint8_t* configData, uint32_t configSize);
    int Report(uint8_t* data, uint32_t dataSize);
    int ReportOptimize(RandomWriteCtx* randomWrite);
    int Stop();

    int64_t GetUserHz();

    // for UT
    void SetPath(std::string path)
    {
        path_ = path;
    };

private:
    template <typename T> bool WriteProcesseList(T& processData);

    DIR* OpenDestDir(const char* dirPath);
    int32_t GetValidPid(DIR* dirp);
    std::vector<int> OpenProcPidFiles(int32_t pid);
    int32_t ReadProcPidFile(int32_t pid, const char* pFileName);

    template <typename T> void WriteProcessInfo(T& processData, int32_t pid);

    template <typename T> void WriteProcess(T& processinfo, const char* pFile, uint32_t fileLen, int32_t pid);

    template <typename T> void SetProcessInfo(T& processinfo, int key, const char* word);

    bool BufnCmp(const char* src, int srcLen, const char* key, int keyLen);
    bool addPidBySort(int32_t pid);
    int GetProcStatusId(const char* src, int srcLen);

    template <typename T> bool WriteCpuUsageData(int pid, T& cpuInfo);

    bool ReadCpuUsage(int pid, uint64_t& cpuTime);
    uint32_t GetCpuUsageData(const std::string& line, uint64_t& cpuTime);
    bool ReadBootTime(int pid, uint64_t& bootTime);
    uint32_t GetBootData(const std::string& line, uint64_t& bootTime);

    template <typename T> bool WriteThreadData(int pid, T& cpuInfo);

    bool FindFirstNum(char** p);
    bool GetValidValue(char* p, uint64_t& num);
    bool FindFirstSpace(char** p);

    template <typename T> bool GetDiskioData(std::string& line, T& diskioInfo);

    template <typename T> bool WriteDiskioData(int pid, T& processinfo);

    template <typename T> bool WritePssData(int pid, T& processinfo);

    ProcessConfig protoConfig_;
    std::unique_ptr<uint8_t[]> buffer_;
    std::vector<int32_t> pids_;
    std::string path_;
    int32_t err_;
    std::unordered_map<int, uint64_t> cpuTime_ = {};
    std::unordered_map<int, uint64_t> bootTime_ = {};
};

#endif
