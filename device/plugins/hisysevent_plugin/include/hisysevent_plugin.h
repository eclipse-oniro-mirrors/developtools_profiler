/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HISYSEVENT_PLUGIN_H
#define HISYSEVENT_PLUGIN_H

#include "hisysevent_plugin_config.pb.h"
#include "hisysevent_plugin_result.pb.h"
#include "logging.h"
#include "plugin_module_api.h"

#include <stdio.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

class HisyseventPlugin {
public:
    HisyseventPlugin();
    ~HisyseventPlugin();
    int Start(const uint8_t* configData, uint32_t configSize);
    int Stop();
    void Run(void);

    int SetWriter(WriterStruct* writer);

private:
    bool InitHisyseventCmd();

    std::string GetCmdline();
    static FILE* CustomPopen(char* const command[], const char* type);
    static int CustomPclose(FILE* fp);

    bool ParseSyseventLineInfo(const char* data, size_t len, HisyseventInfo &dataProto);

private:
    std::vector<char*> fullCmd_;

    std::mutex mutex_;
    std::thread workThread_;
    std::atomic<bool> running_ = true;

    std::unique_ptr<FILE, int (*)(FILE*)> fp_;

    HisyseventConfig protoConfig_;
    std::vector<char> protoBuffer_;
    WriterStruct* resultWriter_ = nullptr;
};
#endif // !HISYSEVENT_PLUGIN_H
