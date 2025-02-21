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

#include "callstack_test.h"
#include "virtual_runtime.h"
#include "get_thread_id.h"
using namespace testing::ext;
using namespace std;
using namespace OHOS::HiviewDFX;
namespace OHOS {
namespace Developtools {
namespace NativeDaemon {
class CallStackTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    default_random_engine rnd_;
};

void CallStackTest::SetUpTestCase() {}

void CallStackTest::TearDownTestCase() {}

void CallStackTest::SetUp() {}

void CallStackTest::TearDown() {}

/**
 * @tc.name: LibUnwindEmptyFunc
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, LibUnwindEmptyFunc, TestSize.Level1)
{
    CallStack callStack = {};
    unw_addr_space_t as = {};
    unw_word_t word = {};
    unw_word_t *wordPtr = {};
    void *voidPtr = {};
    char *buf = {};
    size_t size = {};
    unw_proc_info_t pi = {};
    unw_regnum_t rn = {};
    unw_fpreg_t fp = {};
    unw_cursor_t t = {};
    EXPECT_LE(CallStack::getProcName(as, word, buf, size, wordPtr, voidPtr), 0);
    CallStack::PutUnwindInfo(as, &pi, voidPtr);
    EXPECT_LE(CallStack::AccessFpreg(as, rn, &fp, 0, voidPtr), 0);
    EXPECT_LE(CallStack::Resume(as, &t, voidPtr), 0);
}

/**
 * @tc.name: GetUnwErrorName
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, GetUnwErrorName, TestSize.Level1)
{
    EXPECT_STREQ(CallStack::GetUnwErrorName(UNW_ENOINFO).c_str(), "UNKNOW_UNW_ERROR");
    EXPECT_STRNE(CallStack::GetUnwErrorName(-UNW_ENOINFO).c_str(), "UNKNOW_UNW_ERROR");
}

/**
 * @tc.name: UnwindCallStack
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(CallStackTest, UnwindCallStack, TestSize.Level1)
{
#if is_linux
    return;
#endif

    std::vector<u64> regs;
    std::vector<u8> data;
    LoadFromFile(PATH_RESOURCE_TEST_DWARF_DATA + TEST_DWARF_USER_REGS_0, regs);
    LoadFromFile(PATH_RESOURCE_TEST_DWARF_DATA + TEST_DWARF_USER_DATA_0, data);
    if (regs.size() > 0 and data.size() > 0) {
#ifdef __arm__
        ASSERT_EQ(regs.size(), 16u);
#endif

    std::set<std::unique_ptr<SymbolsFile>, CCompareSymbolsFile> symbolsFiles;
    auto &symbolsFile = *symbolsFiles.insert(SymbolsFile::CreateSymbolsFile(SYMBOL_ELF_FILE,
        PATH_RESOURCE_TEST_DWARF_DATA + TEST_DWARF_ELF)).first;
    ASSERT_EQ(symbolsFile->LoadSymbols(), true);
    // fix the name
    symbolsFile->filePath_ = TEST_DWARF_MMAP.front().fileName;
    std::shared_ptr<VirtualRuntime> runtime = std::make_shared<VirtualRuntime>();
    VirtualThread thread(getpid(), get_thread_id(), symbolsFiles, runtime.get(), false);
    MakeMaps(thread);
    std::vector<CallFrame> callFrames;
    CallStack callStack;

    u64* sppcRegs = new u64[2];
    sppcRegs[0] = regs[PERF_REG_ARM_SP_IDX];
    sppcRegs[1] = regs[PERF_REG_ARM_PC_IDX];
    callStack.UnwindCallStack(thread, sppcRegs, 2, data.data(), data.size(),
                                  callFrames);
    delete[] sppcRegs;
    sppcRegs = nullptr;
#ifdef __arm__
        ASSERT_LE(TEST_DWARF_FRAMES.size(), callFrames.size());
        for (size_t i = 0; i < TEST_DWARF_FRAMES.size(); i++) {
            EXPECT_EQ(TEST_DWARF_FRAMES[i].ip, callFrames[i].ip_);
            EXPECT_EQ(TEST_DWARF_FRAMES[i].sp, callFrames[i].sp_);
        }
#endif
    }
}
} // namespace NativeDaemon
} // namespace Developtools
} // namespace OHOS
