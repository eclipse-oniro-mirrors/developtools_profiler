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
#include <hwext/gtest-ext.h>
#include <hwext/gtest-tag.h>
#include <unistd.h>

#include "logging.h"
#include "result_demuxer.h"

using namespace testing::ext;

namespace {
constexpr int DATA_MAX_SIZE = 10; // set max size 10;

class ResultDemuxerTest : public ::testing::Test {
protected:
    std::string path = "demux.bin";
    ProfilerDataRepeaterPtr repeater;
    PluginSessionManagerPtr pluginSessionManager;

    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void SetUp() override
    {
        repeater = std::make_shared<ProfilerDataRepeater>(DATA_MAX_SIZE);
        pluginSessionManager = std::make_shared<PluginSessionManager>(std::make_shared<PluginService>());
    }

    void TearDown() override {}
};

/**
 * @tc.name: server
 * @tc.desc: Class-strengthening.
 * @tc.type: FUNC
 */
HWTEST_F(ResultDemuxerTest, CtorDtor, TestSize.Level1)
{
    auto demuxer = std::make_shared<ResultDemuxer>(repeater, pluginSessionManager);
    EXPECT_NE(demuxer, nullptr);
}

/**
 * @tc.name: server
 * @tc.desc: set trace writer.
 * @tc.type: FUNC
 */
HWTEST_F(ResultDemuxerTest, SetTraceWriter, TestSize.Level1)
{
    auto demuxer = std::make_shared<ResultDemuxer>(repeater, pluginSessionManager);
    ASSERT_NE(demuxer, nullptr);

    demuxer->SetTraceWriter(nullptr);

    auto writer = std::make_shared<TraceFileWriter>(path);
    EXPECT_NE(writer, nullptr);
    demuxer->SetTraceWriter(writer);
}

/**
 * @tc.name: server
 * @tc.desc: set server writer.
 * @tc.type: FUNC
 */
HWTEST_F(ResultDemuxerTest, SetServerWriter, TestSize.Level1)
{
    auto demuxer = std::make_shared<ResultDemuxer>(repeater, pluginSessionManager);
    ASSERT_NE(demuxer, nullptr);
}

/**
 * @tc.name: server
 * @tc.desc: set take results.
 * @tc.type: FUNC
 */
HWTEST_F(ResultDemuxerTest, StartTakeResults, TestSize.Level1)
{
    auto demuxer = std::make_shared<ResultDemuxer>(repeater, pluginSessionManager);
    ASSERT_NE(demuxer, nullptr);

    auto writer = std::make_shared<TraceFileWriter>(path);
    EXPECT_NE(writer, nullptr);
    demuxer->SetTraceWriter(writer);

    const int putCount = 20;
    const int putDelayUs = 20 * 1000;
    demuxer->StartTakeResults();
    std::thread dataProducer([=] {
        for (int i = 0; i < putCount; i++) {
            auto pluginData = std::make_shared<ProfilerPluginData>();
            ASSERT_NE(pluginData, nullptr);
            pluginData->set_name("test-" + std::to_string(i));
            pluginData->set_status(i);
            repeater->PutPluginData(pluginData);
            HILOG_DEBUG(LOG_CORE, "put test data %d...", i);
            usleep(putDelayUs);
        }
        repeater->PutPluginData(nullptr);
    });

    HILOG_DEBUG(LOG_CORE, "waiting producer thread done...");
    dataProducer.join();
}

/**
 * @tc.name: server
 * @tc.desc: stop take results.
 * @tc.type: FUNC
 */
HWTEST_F(ResultDemuxerTest, StopTakeResults, TestSize.Level1)
{
    auto demuxer = std::make_shared<ResultDemuxer>(repeater, pluginSessionManager);
    ASSERT_NE(demuxer, nullptr);

    auto writer = std::make_shared<TraceFileWriter>(path);
    EXPECT_NE(writer, nullptr);
    demuxer->SetTraceWriter(writer);

    const int putCount = 30;
    const int putDelayUs = 20 * 1000;
    demuxer->StartTakeResults();
    std::thread dataProducer([=] {
        for (int i = 0; i < putCount; i++) {
            auto pluginData = std::make_shared<ProfilerPluginData>();
            ASSERT_NE(pluginData, nullptr);
            pluginData->set_name("AB-" + std::to_string(i));
            pluginData->set_status(i);

            HILOG_DEBUG(LOG_CORE, "put test data %d...", i);
            if (!repeater->PutPluginData(pluginData)) {
                HILOG_WARN(LOG_CORE, "put test data %d FAILED!", i);
                break;
            }
            usleep(putDelayUs);
        }
    });

    usleep((putCount / 2) * putDelayUs);
    demuxer->StopTakeResults();

    repeater->Close();
    HILOG_DEBUG(LOG_CORE, "waiting producer thread done...");
    dataProducer.join();
}
} // namespace