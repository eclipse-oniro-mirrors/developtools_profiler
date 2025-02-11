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
#include <iostream>
#include <sstream>
#include "include/sp_utils.h"
#include "include/Dubai.h"
#include "include/sp_log.h"
#include "common.h"
namespace OHOS {
namespace SmartPerf {
void Dubai::DumpDubaiBegin()
{
    std::string result;
    std::string dumpBubaiB = HIDUMPER_CMD_MAP.at(HidumperCmd::DUMPER_DUBAI_B);
    SPUtils::LoadCmd(dumpBubaiB, result);
    LOGI("Dubai::DumpDubaiBegin");
}
void Dubai::DumpDubaiFinish()
{
    std::string result;
    std::string dumpBubaiF = HIDUMPER_CMD_MAP.at(HidumperCmd::DUMPER_DUBAI_F);
    SPUtils::LoadCmd(dumpBubaiF, result);
    LOGI("Dubai::DumpDubaiFinish");
}

void Dubai::MoveDubaiDb()
{
    std::string result;
    std::string cpdubaiPath = CMD_COMMAND_MAP.at(CmdCommand::DUBAI_CP);
    std::string cpdubaiPathChmod = CMD_COMMAND_MAP.at(CmdCommand::DUBAI_CHMOD);
    SPUtils::LoadCmd(cpdubaiPath, result);
    SPUtils::LoadCmd(cpdubaiPathChmod, result);
}
}
}
