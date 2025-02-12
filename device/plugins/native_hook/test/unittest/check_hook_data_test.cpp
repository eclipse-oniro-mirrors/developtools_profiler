/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
#include <fcntl.h>
#include <hwext/gtest-ext.h>
#include <hwext/gtest-tag.h>
#include <vector>
#include <sys/syscall.h>

#include "buffer_splitter.h"
#include "logging.h"

#pragma clang optimize off

using namespace testing::ext;

namespace {
const int DEFAULT_MALLOC_SIZE = 10;
const int DEFAULT_CALLOC_SIZE = 100;
const int DEFAULT_REALLOC_SIZE = 1000;
const int DATA_SIZE = 50;
const int WAIT_KILL_SIGNL = 4;
const int SLEEP_TIME = 5;
const int WAIT_FLUSH = 2;

const std::string DEFAULT_NATIVE_DAEMON_PATH("/system/bin/native_daemon");
std::string DEFAULT_PATH("/data/local/tmp/");
const int g_shareMemorySize = 1000 * 4096;
const int g_bufferSize = 100 * 1024;
const int g_defaultDepth = 32;
const int g_callocDepth = 13;
const int g_reallocDepth = 10;
const int g_mallocVecSize = 5;
const int g_freeVecSize = 4;
const int g_mallocGetDataSize = 3;
const int g_freeGetDataSize = 2;
std::unique_ptr<uint8_t[]> g_buffer = std::make_unique<uint8_t[]>(g_bufferSize);

using StaticSpace = struct {
    int data[DATA_SIZE];
} ;

class CheckHookDataTest : public ::testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}

    void StartDaemonProcessArgs(int pid, std::string outFile)
    {
        int processNum = fork();
        if (processNum == 0) {
            // start running native_daemon -o -s -p
            execl(DEFAULT_NATIVE_DAEMON_PATH.c_str(), DEFAULT_NATIVE_DAEMON_PATH.c_str(), "-o", outFile.c_str(),
                "-s", std::to_string(g_shareMemorySize).c_str(), "-p", std::to_string(pid).c_str(), nullptr);
            _exit(1);
        } else {
            g_daemonPid = processNum;
        }
    }

    void StartDaemonProcessArgsDepth(int pid, int setHookDepth, std::string outFile)
    {
        int processNum = fork();
        if (processNum == 0) {
            // start running native_daemon -o -s -p -d
            execl(DEFAULT_NATIVE_DAEMON_PATH.c_str(), DEFAULT_NATIVE_DAEMON_PATH.c_str(), "-o", outFile.c_str(),
                "-s", std::to_string(g_shareMemorySize).c_str(), "-p", std::to_string(pid).c_str(),
                "-d", std::to_string(setHookDepth).c_str(), nullptr);
            _exit(1);
        } else {
            g_daemonSetDepthPid = processNum;
        }
    }

    void StopProcess(int processNum)
    {
        std::string stopCmd = "kill -9 " + std::to_string(processNum);
        system(stopCmd.c_str());
    }

    int32_t ReadFile(std::string file)
    {
        int fd = -1;
        ssize_t bytesRead = 0;
        char filePath[PATH_MAX + 1] = {0};

        if (snprintf_s(filePath, sizeof(filePath), sizeof(filePath) - 1, "%s", file.c_str()) < 0) {
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "snprintf_s(%s) error, errno(%d:%s)", file.c_str(), errno, buf);
            return -1;
        }

        char* realPath = realpath(filePath, nullptr);
        if (realPath == nullptr) {
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "realpath(%s) failed, errno(%d:%s)", file.c_str(), errno, buf);
            return -1;
        }

        fd = open(realPath, O_RDONLY | O_CLOEXEC);
        if (fd == -1) {
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "%s:failed to open(%s), errno(%d:%s)", __func__, realPath, errno, buf);
            return -1;
        }
        if (g_buffer == nullptr) {
            HILOG_ERROR(LOG_CORE, "%s:empty address, g_buffer is NULL", __func__);
            close(fd);
            return -1;
        }
        bytesRead = read(fd, g_buffer.get(), g_bufferSize - 1);
        if (bytesRead <= 0) {
            close(fd);
            HILOG_ERROR(LOG_CORE, "%s:failed to read(%s), errno=%d", __func__, realPath, errno);
            return -1;
        }
        close(fd);
        free(realPath);

        return bytesRead;
    }

    void DepthFree(int depth, void *p)
    {
        StaticSpace staticeData;
        if (depth == 0) {
            staticeData.data[0] = 1;
            free(p);
            return;
        }
        return (DepthFree(depth - 1, p));
    }

    char *DepthMalloc(int depth)
    {
        StaticSpace staticeData;
        if (depth == 0) {
            staticeData.data[0] = 1;
            return reinterpret_cast<char *>(malloc(DEFAULT_MALLOC_SIZE));
        }
        return (DepthMalloc(depth - 1));
    }

    void ApplyForMalloc(int depth)
    {
        char *p = DepthMalloc(depth);
        if (!p) {
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "ApplyForMalloc: malloc failure, errno(%d:%s)", errno, buf);
            return;
        }
        DepthFree(depth, p);
    }

    void StartMallocProcess(int depth, int& pid)
    {
        int processNum = fork();
        if (processNum == 0) {
            while (1) {
                ApplyForMalloc(depth);
                sleep(1);
            }
        } else {
            pid = processNum;
        }
    }

    char *DepthCalloc(int depth, int callocSize)
    {
        StaticSpace staticeData;
        if (depth == 0) {
            staticeData.data[0] = 1;
            return reinterpret_cast<char *>(calloc(sizeof(char), callocSize));
        }
        return (DepthCalloc(depth - 1, callocSize));
    }

    void ApplyForCalloc(int depth)
    {
        int callocSize = DEFAULT_CALLOC_SIZE / sizeof(char);
        char *p = DepthCalloc(depth, callocSize);
        if (!p) {
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "ApplyForCalloc: calloc failure, errno(%d:%s)", errno, buf);
            return;
        }
        DepthFree(depth, p);
    }

    void StartCallocProcess(int depth, int& pid)
    {
        int processNum = fork();
        if (processNum == 0) {
            sleep(WAIT_KILL_SIGNL);
            auto ret = malloc(DEFAULT_MALLOC_SIZE);
            free(ret);
            while (1) {
                ApplyForCalloc(depth);
                sleep(1);
            }
        } else {
            pid = processNum;
        }
    }

    char *DepthRealloc(int depth, void *p, int reallocSize)
    {
        StaticSpace staticeData;
        if (depth == 0) {
            staticeData.data[0] = 1;
            return reinterpret_cast<char *>(realloc(p, reallocSize));
        }
        return (DepthRealloc(depth - 1, p, reallocSize));
    }

    void ApplyForRealloc(int depth)
    {
        int reallocSize = DEFAULT_REALLOC_SIZE;
        char *p = reinterpret_cast<char *>(malloc(DEFAULT_MALLOC_SIZE));
        if (!p) {
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "ApplyForRealloc: malloc failure, errno(%d:%s)", errno, buf);
            return;
        }
        char *np = DepthRealloc(depth, p, reallocSize);
        if (!np) {
            free(p);
            const int bufSize = 256;
            char buf[bufSize] = { 0 };
            strerror_r(errno, buf, bufSize);
            HILOG_ERROR(LOG_CORE, "ApplyForRealloc: realloc failure, errno(%d:%s)", errno, buf);
            return;
        }
        DepthFree(depth, np);
    }

    void StartReallocProcess(int depth, int& pid)
    {
        int processNum = fork();
        if (processNum == 0) {
            while (1) {
                ApplyForRealloc(depth);
                sleep(1);
            }
        } else {
            pid = processNum;
        }
    }

    bool Getdata(BufferSplitter& totalbuffer, std::vector<std::string>& hookVec, char delimiter)
    {
        totalbuffer.NextWord(delimiter);
        if (!totalbuffer.CurWord()) {
            return false;
        }
        std::string curWord = std::string(totalbuffer.CurWord(), totalbuffer.CurWordSize());
        hookVec.push_back(curWord);
        return true;
    }

private:
    int g_daemonPid = -1;
    int g_daemonSetDepthPid = -1;
};

/**
 * @tc.name: native hook
 * @tc.desc: Test hook malloc normal process.
 * @tc.type: FUNC
 */
HWTEST_F(CheckHookDataTest, DFX_DFR_Hiprofiler_0080, Function | MediumTest | Level1)
{
    int setDepth = 100; // 递归深度大于hook默认深度30，测试文本
    int mallocPid = -1;
    std::string outFile = DEFAULT_PATH + "hooktest_malloc.txt";
    StartMallocProcess(setDepth, mallocPid);
    sleep(1);
    StartDaemonProcessArgs(mallocPid, outFile);

    sleep(1);
    std::string cmd = "kill -36 " + std::to_string(mallocPid);
    system(cmd.c_str());

    sleep(SLEEP_TIME); // 等待生成文本
    std::string cmdEnd = "kill -37 " + std::to_string(mallocPid);
    system(cmdEnd.c_str());
    sleep(WAIT_FLUSH);
    StopProcess(mallocPid);
    StopProcess(g_daemonPid);

    int32_t ret = ReadFile(outFile);
    ASSERT_NE(ret, -1);

    BufferSplitter totalbuffer(const_cast<char*>((char*)g_buffer.get()), ret + 1);
    std::vector<std::string> hookVec;
    std::string addr = "";
    int depth = 0;
    int addrPos = 3;
    bool isFirstHook = true;
    do {
        char delimiter = ';';
        Getdata(totalbuffer, hookVec, delimiter);

        if (hookVec[0] == "malloc" && !isFirstHook) {
            for (int i = 0; i < g_mallocGetDataSize; i++) {
                EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            }
            delimiter = '\n';
            EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            ASSERT_EQ(static_cast<int>(hookVec.size()), g_mallocVecSize);
            ASSERT_EQ(atoi(hookVec[4].c_str()), DEFAULT_MALLOC_SIZE);

            addr = hookVec[addrPos];
            depth = 0;
        } else if (hookVec[0] == "free" && !isFirstHook) {
            for (int i = 0; i < g_freeGetDataSize; i++) {
                EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            }
            delimiter = '\n';
            EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            ASSERT_EQ(static_cast<int>(hookVec.size()), g_freeVecSize);
            EXPECT_STREQ(hookVec[addrPos].c_str(), addr.c_str());
            EXPECT_EQ(depth, g_defaultDepth);

            isFirstHook = false;
            addr = "";
            depth = 0;
        } else {
            depth++;
        }

        hookVec.clear();
    } while (totalbuffer.NextLine());
}

/**
 * @tc.name: native hook
 * @tc.desc: Test hook calloc normal process.
 * @tc.type: FUNC
 */
HWTEST_F(CheckHookDataTest, DFX_DFR_Hiprofiler_0090, Function | MediumTest | Level3)
{
    int setDepth = 1; // 递归深度小于hook深度100，测试文本
    int setHookDepth = 100;
    int callocPid = -1;
    std::string outFile = DEFAULT_PATH + "hooktest_calloc.txt";
    StartCallocProcess(setDepth, callocPid);
    sleep(1);
    StartDaemonProcessArgsDepth(callocPid, setHookDepth, outFile);

    sleep(1);
    std::string cmd = "kill -36 " + std::to_string(callocPid);
    system(cmd.c_str());

    sleep(SLEEP_TIME); // 等待生成文本
    std::string cmdEnd = "kill -37 " + std::to_string(callocPid);
    system(cmdEnd.c_str());
    sleep(WAIT_FLUSH);
    StopProcess(callocPid);
    StopProcess(g_daemonSetDepthPid);

    int32_t ret = ReadFile(outFile);
    ASSERT_NE(ret, -1);

    BufferSplitter totalbuffer(const_cast<char*>((char*)g_buffer.get()), ret + 1);
    std::vector<std::string> hookVec;
    std::string addr = "";
    int depth = 0;
    int addrPos = 3;
    bool isFirstHook = true;
    do {
        char delimiter = ';';
        Getdata(totalbuffer, hookVec, delimiter);

        if (hookVec[0] == "malloc" && !isFirstHook) {
            for (int i = 0; i < g_mallocGetDataSize; i++) {
                EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            }
            delimiter = '\n';
            EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            ASSERT_EQ(static_cast<int>(hookVec.size()), g_mallocVecSize);
            ASSERT_EQ(atoi(hookVec[4].c_str()), DEFAULT_CALLOC_SIZE);

            addr = hookVec[addrPos];
            depth = 0;
        } else if (hookVec[0] == "free" && !isFirstHook) {
            for (int i = 0; i < g_freeGetDataSize; i++) {
                EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            }
            delimiter = '\n';
            EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            ASSERT_EQ(static_cast<int>(hookVec.size()), g_freeVecSize);
            EXPECT_STREQ(hookVec[addrPos].c_str(), addr.c_str());
            EXPECT_GE(depth, g_callocDepth);

            isFirstHook = false;
            addr = "";
            depth = 0;
        } else {
            depth++;
        }

        hookVec.clear();
    } while (totalbuffer.NextLine());
}

/**
 * @tc.name: native hook
 * @tc.desc: Test hook realloc normal process.
 * @tc.type: FUNC
 */
HWTEST_F(CheckHookDataTest, DFX_DFR_Hiprofiler_0100, Function | MediumTest | Level3)
{
    int setDepth = 100; // realloc测试文本
    int reallocPid = -1;
    std::string outFile = DEFAULT_PATH + "hooktest_realloc.txt";
    StartReallocProcess(setDepth, reallocPid);
    sleep(1);
    StartDaemonProcessArgs(reallocPid, outFile);

    sleep(1);
    std::string cmd = "kill -36 " + std::to_string(reallocPid);
    system(cmd.c_str());

    sleep(SLEEP_TIME); // 等待生成文本
    std::string cmdEnd = "kill -37 " + std::to_string(reallocPid);
    system(cmdEnd.c_str());
    sleep(WAIT_FLUSH);
    StopProcess(reallocPid);
    StopProcess(g_daemonPid);

    int32_t ret = ReadFile(outFile);
    ASSERT_NE(ret, -1);

    BufferSplitter totalbuffer(const_cast<char*>((char*)g_buffer.get()), ret + 1);
    std::vector<std::string> hookVec;
    std::string mallocAddr = "";
    std::string reallocAddr = "";
    int depth = 0;
    int addrPos = 3;
    bool isFirstHook = true;
    bool isRealloc = false;
    do {
        char delimiter = ';';
        Getdata(totalbuffer, hookVec, delimiter);

        if (hookVec[0] == "malloc" && !isFirstHook) {
            for (int i = 0; i < g_mallocGetDataSize; i++) {
                EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            }
            delimiter = '\n';
            EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            ASSERT_EQ(static_cast<int>(hookVec.size()), g_mallocVecSize);

            if (isRealloc) {
                reallocAddr = hookVec[addrPos];
                ASSERT_GE(atoi(hookVec[4].c_str()), DEFAULT_REALLOC_SIZE);
                EXPECT_GE(depth, g_reallocDepth);
                isFirstHook = false;
            } else {
                mallocAddr = hookVec[addrPos];
                ASSERT_EQ(atoi(hookVec[4].c_str()), DEFAULT_MALLOC_SIZE);
            }

            isRealloc = true;
            depth = 0;
        } else if (hookVec[0] == "free" && !isFirstHook) {
            for (int i = 0; i < g_freeGetDataSize; i++) {
                EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            }
            delimiter = '\n';
            EXPECT_TRUE(Getdata(totalbuffer, hookVec, delimiter));
            ASSERT_EQ(static_cast<int>(hookVec.size()), g_freeVecSize);

            if (isRealloc) {
                EXPECT_STREQ(hookVec[addrPos].c_str(), reallocAddr.c_str());
                reallocAddr = "";
            } else {
                EXPECT_STREQ(hookVec[addrPos].c_str(), mallocAddr.c_str());
                mallocAddr = "";
            }

            isRealloc = false;
            depth = 0;
        } else {
            depth++;
        }

        hookVec.clear();
    } while (totalbuffer.NextLine());
}
}

#pragma clang optimize on
