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

#include <fcntl.h>
#include <hwext/gtest-ext.h>
#include <hwext/gtest-tag.h>
#include <iostream>
#include <string>
#include <unistd.h>

#include "file.h"
#include "trace_streamer_selector.h"
constexpr size_t G_FILE_PERMISSION = 664;

using namespace testing::ext;
using namespace SysTuning;
using namespace SysTuning::TraceStreamer;
namespace SysTuning {
namespace TraceStreamer {
class ParserTest : public testing::Test {
protected:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
};

/**
 * @tc.name: BytraceParserTest
 * @tc.desc: Test bytrace parsing TXT file to export database
 * @tc.type: FUNC
 */
HWTEST_F(ParserTest, BytraceParserTest, TestSize.Level1)
{
    TS_LOGI("test25-1");
    const std::string tracePath = "data/resource/ut_bytrace_input_full.txt";
    const std::string utGoldDb = "data/resource/ut_bytrace_input_full_gold.db";
    const std::string dbPath = "data/resource/out_db1.db";
    constexpr size_t readSize = 1024 * 1024;
    constexpr uint32_t lineLength = 256;

    if (access(tracePath.c_str(), F_OK) == 0) {
        std::unique_ptr<SysTuning::TraceStreamer::TraceStreamerSelector> ta =
            std::make_unique<SysTuning::TraceStreamer::TraceStreamerSelector>();
        ta->EnableMetaTable(false);
        ta->SetCleanMode(false);
        int fd(base::OpenFile(tracePath, O_RDONLY, G_FILE_PERMISSION));
        while (true) {
            std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(readSize);
            auto rsize = base::Read(fd, buf.get(), readSize);
            if (rsize == 0) {
                break;
            }
            if (rsize < 0) {
                TS_LOGD("Reading trace file failed (errno: %d, %s)", errno, strerror(errno));
                break;
            }
            if (!ta->ParseTraceDataSegment(std::move(buf), rsize)) {
                break;
            };
        }
        ta->WaitForParserEnd();
        close(fd);
        ta->ExportDatabase(dbPath);
        ta->Clear();
        EXPECT_TRUE(access(dbPath.c_str(), F_OK) == 0);
    } else {
        EXPECT_TRUE(false);
    }

    if (access(utGoldDb.c_str(), F_OK) == 0) {
        FILE* file1 = nullptr;
        FILE* file2 = nullptr;
        char line1[lineLength];
        char line2[lineLength];
        const std::string command1 = "md5sum data/resource/ut_bytrace_input_full_gold.db";
        const std::string md5DbPath = "md5sum "+ dbPath;
        file1 = popen(command1.c_str(), "r");
        file2 = popen(md5DbPath.c_str(), "r");
        if (file1 && file2) {
            if (fgets(line1, lineLength, file1) != nullptr && fgets(line2, lineLength, file2) != nullptr) {
                std::string str1(line1);
                std::string str2(line2);
                str1 = str1.substr(0, str1.find_first_of(' '));
                str2 = str2.substr(0, str2.find_first_of(' '));
                EXPECT_TRUE(str1.compare(str2) == 0);
            }
        }
    } else {
        EXPECT_TRUE(false);
    }

    if (access(dbPath.c_str(), F_OK) == 0) {
        remove(dbPath.c_str());
    }
}

/**
 * @tc.name: HtraceParserTest
 * @tc.desc: Test htrace parsing binary file export database
 * @tc.type: FUNC
 */
HWTEST_F(ParserTest, HtraceParserTest, TestSize.Level1)
{
    TS_LOGI("test25-2");
    const std::string tracePath = "data/resource/htrace.bin";
    const std::string utGoldDb = "data/resource/htrace_gold.db";
    const std::string dbPath = "data/resource/out_db2.db";
    constexpr size_t readSize = 1024;
    constexpr uint32_t lineLength = 256;

    if (access(tracePath.c_str(), F_OK) == 0) {
        std::unique_ptr<SysTuning::TraceStreamer::TraceStreamerSelector> ta =
            std::make_unique<SysTuning::TraceStreamer::TraceStreamerSelector>();
        ta->EnableMetaTable(false);
        ta->SetCleanMode(false);
        int fd(base::OpenFile(tracePath, O_RDONLY, G_FILE_PERMISSION));
        while (true) {
            std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(readSize);
            auto rsize = base::Read(fd, buf.get(), readSize);

            if (rsize == 0) {
                break;
            }
            if (rsize < 0) {
                TS_LOGD("Reading trace file over (errno: %d, %s)", errno, strerror(errno));
                break;
            }
            if (!ta->ParseTraceDataSegment(std::move(buf), rsize)) {
                break;
            };
        }
        ta->WaitForParserEnd();
        close(fd);
        ta->ExportDatabase(dbPath);
        ta->Clear();
        EXPECT_TRUE(access(dbPath.c_str(), F_OK) == 0);
    } else {
        EXPECT_TRUE(false);
    }

    if (access(utGoldDb.c_str(), F_OK) == 0) {
        FILE* file1 = nullptr;
        FILE* file2 = nullptr;
        char line1[lineLength];
        char line2[lineLength];
        const std::string command1 = "md5sum data/resource/htrace_gold.db";
        const std::string md5DbPath = "md5sum "+ dbPath;
        file1 = popen(command1.c_str(), "r");
        file2 = popen(md5DbPath.c_str(), "r");
        if (file1 && file2) {
            if (fgets(line1, lineLength, file1) != nullptr && fgets(line2, lineLength, file2) != nullptr) {
                std::string str1(line1);
                std::string str2(line2);
                str1 = str1.substr(0, str1.find_first_of(' '));
                str2 = str2.substr(0, str2.find_first_of(' '));
                EXPECT_TRUE(str1.compare(str2) == 0);
            }
        }
    } else {
        EXPECT_TRUE(false);
    }

    if (access(dbPath.c_str(), F_OK) == 0) {
        remove(dbPath.c_str());
    }
}

/**
 * @tc.name: HtraceAndPerfParserTest
 * @tc.desc: Test parsing htrace and perf binary file export database
 * @tc.type: FUNC
 */
HWTEST_F(ParserTest, HtraceAndPerfParserTest, TestSize.Level1)
{
    TS_LOGI("test25-3");
    const std::string tracePath = "data/resource/htrace_perf.bin";
    const std::string utGoldDb = "data/resource/htrace_perf_gold.db";
    const std::string dbPath = "data/resource/out_db3.db";
    constexpr size_t readSize = 1024;
    constexpr uint32_t lineLength = 256;

    if (access(tracePath.c_str(), F_OK) == 0) {
        std::unique_ptr<SysTuning::TraceStreamer::TraceStreamerSelector> ta =
            std::make_unique<SysTuning::TraceStreamer::TraceStreamerSelector>();
        ta->EnableMetaTable(false);
        ta->SetCleanMode(false);
        int fd(base::OpenFile(tracePath, O_RDONLY, G_FILE_PERMISSION));
        while (true) {
            std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(readSize);
            auto rsize = base::Read(fd, buf.get(), readSize);

            if (rsize == 0) {
                break;
            }
            if (rsize < 0) {
                TS_LOGD("Reading trace file over (errno: %d, %s)", errno, strerror(errno));
                break;
            }
            if (!ta->ParseTraceDataSegment(std::move(buf), rsize)) {
                break;
            };
        }
        ta->WaitForParserEnd();
        close(fd);
        ta->ExportDatabase(dbPath);
        ta->Clear();
        EXPECT_TRUE(access(dbPath.c_str(), F_OK) == 0);
    } else {
        EXPECT_TRUE(false);
    }

    if (access(utGoldDb.c_str(), F_OK) == 0) {
        FILE* file1 = nullptr;
        FILE* file2 = nullptr;
        char line1[lineLength];
        char line2[lineLength];
        const std::string command1 = "md5sum data/resource/htrace_perf_gold.db";
        const std::string md5DbPath = "md5sum "+ dbPath;
        file1 = popen(command1.c_str(), "r");
        file2 = popen(md5DbPath.c_str(), "r");
        if (file1 && file2) {
            if (fgets(line1, lineLength, file1) != nullptr && fgets(line2, lineLength, file2) != nullptr) {
                std::string str1(line1);
                std::string str2(line2);
                str1 = str1.substr(0, str1.find_first_of(' '));
                str2 = str2.substr(0, str2.find_first_of(' '));
                EXPECT_TRUE(str1.compare(str2) == 0);
            }
        }
    } else {
        EXPECT_TRUE(false);
    }

    if (access(dbPath.c_str(), F_OK) == 0) {
        remove(dbPath.c_str());
    }
}

/**
 * @tc.name: HtraceAndEbpfParserTest
 * @tc.desc: Test parsing htrace and ebpf binary file export database
 * @tc.type: FUNC
 */
HWTEST_F(ParserTest, HtraceAndEbpfParserTest, TestSize.Level1)
{
    TS_LOGI("test25-4");
    const std::string tracePath = "data/resource/htrace_ebpf.bin";
    const std::string utGoldDb = "data/resource/htrace_ebpf_gold.db";
    const std::string dbPath = "data/resource/out_db4.db";
    constexpr size_t readSize = 1024;
    constexpr uint32_t lineLength = 256;

    if (access(tracePath.c_str(), F_OK) == 0) {
        std::unique_ptr<SysTuning::TraceStreamer::TraceStreamerSelector> ta =
            std::make_unique<SysTuning::TraceStreamer::TraceStreamerSelector>();
        ta->EnableMetaTable(false);
        ta->SetCleanMode(false);
        int fd(base::OpenFile(tracePath, O_RDONLY, G_FILE_PERMISSION));
        while (true) {
            std::unique_ptr<uint8_t[]> buf = std::make_unique<uint8_t[]>(readSize);
            auto rsize = base::Read(fd, buf.get(), readSize);

            if (rsize == 0) {
                break;
            }
            if (rsize < 0) {
                TS_LOGD("Reading trace file over (errno: %d, %s)", errno, strerror(errno));
                break;
            }
            if (!ta->ParseTraceDataSegment(std::move(buf), rsize)) {
                break;
            };
        }
        ta->WaitForParserEnd();
        close(fd);
        ta->ExportDatabase(dbPath);
        ta->Clear();
        EXPECT_TRUE(access(dbPath.c_str(), F_OK) == 0);
    } else {
        EXPECT_TRUE(false);
    }

    if (access(utGoldDb.c_str(), F_OK) == 0) {
        FILE* file1 = nullptr;
        FILE* file2 = nullptr;
        char line1[lineLength];
        char line2[lineLength];
        const std::string command1 = "md5sum data/resource/htrace_ebpf_gold.db";
        const std::string md5DbPath = "md5sum "+ dbPath;
        file1 = popen(command1.c_str(), "r");
        file2 = popen(md5DbPath.c_str(), "r");
        if (file1 && file2) {
            if (fgets(line1, lineLength, file1) != nullptr && fgets(line2, lineLength, file2) != nullptr) {
                std::string str1(line1);
                std::string str2(line2);
                str1 = str1.substr(0, str1.find_first_of(' '));
                str2 = str2.substr(0, str2.find_first_of(' '));
                EXPECT_TRUE(str1.compare(str2) == 0);
            }
        }
    } else {
        EXPECT_TRUE(false);
    }

    if (access(dbPath.c_str(), F_OK) == 0) {
        remove(dbPath.c_str());
    }
}
} // namespace TraceStreamer
} // namespace SysTuning
