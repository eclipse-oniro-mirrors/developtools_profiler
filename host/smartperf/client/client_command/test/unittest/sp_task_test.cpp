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
#include <exception>
#include <iostream>
#include <string>
#include <thread>
#include <gtest/gtest.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <functional>
#include "sp_utils.h"
#include "sp_log.h"
#include "sp_task.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace SmartPerf {
class SPdaemonTaskTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: CheckTcpParamTestCase
 * @tc.desc: Test CheckTcpParam
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTaskTest, CheckTcpParamTestCase001, TestSize.Level1)
{
    std::string str = "-SESSIONID 12345678 -INTERVAL 1000 -PKG ohos.samples.ecg -c -g -t -p -f -r";
    std::string errorInfo = "";
    SPTask &spTask = SPTask::GetInstance();
    bool flag = spTask.CheckTcpParam(str, errorInfo);
    EXPECT_TRUE(flag);
}

HWTEST_F(SPdaemonTaskTest, CheckTcpParamTestCase002, TestSize.Level1)
{
    std::string str = "";
    std::string errorInfo = "";
    SPTask &spTask = SPTask::GetInstance();
    bool flag = spTask.CheckTcpParam(str, errorInfo);
    EXPECT_FALSE(flag);
}

HWTEST_F(SPdaemonTaskTest, CheckTcpParamTestCase003, TestSize.Level1)
{
    std::string str = "";
    std::string errorInfo = "";
    SPTask &spTask = SPTask::GetInstance();
    bool flag = spTask.CheckTcpParam(str, errorInfo);
    EXPECT_FALSE(flag);
}

/**
 * @tc.name: SPTask::DetectionAndGrab
 * @tc.desc: Test DetectionAndGrab
 * @tc.type: FUNC
 */
HWTEST_F(SPdaemonTaskTest, DetectionAndGrabTestCase001, TestSize.Level1)
{
    bool ret = false;
    std::map<std::string, std::string> templateMap;
    std::string recvStr = "-SESSIONID 12345678 -INTERVAL 1000 -PKG ohos.samples.ecg -c -g -t -p -f -r";
    SPTask::GetInstance().InitTask(recvStr);
    templateMap = SPTask::GetInstance().DetectionAndGrab();

    if (templateMap.empty()) {
        ret = true;
    }

    EXPECT_EQ(ret, true);
}

}
}
