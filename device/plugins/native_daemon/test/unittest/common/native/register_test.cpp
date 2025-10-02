/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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

#include "register_test.h"

#include <bitset>

using namespace testing::ext;
using namespace std;
namespace OHOS {
namespace Developtools {
namespace NativeDaemon {
class RegisterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RegisterTest::SetUpTestCase() {}

void RegisterTest::TearDownTestCase() {}

void RegisterTest::SetUp() {}

void RegisterTest::TearDown() {}

/**
 * @tc.name: GetSupportedRegMask
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, GetSupportedRegMask, TestSize.Level1)
{
    EXPECT_NE(GetSupportedRegMask(ArchType::ARCH_X86), GetSupportedRegMask(ArchType::ARCH_X86_64));
    EXPECT_NE(GetSupportedRegMask(ArchType::ARCH_ARM), GetSupportedRegMask(ArchType::ARCH_ARM64));
    EXPECT_EQ(GetSupportedRegMask(static_cast<ArchType>(100)),
              std::numeric_limits<uint64_t>::max());
    EXPECT_EQ(GetSupportedRegMask(static_cast<ArchType>(-1)), std::numeric_limits<uint64_t>::max());

    std::bitset<64> regMasker;
    regMasker = GetSupportedRegMask(ArchType::ARCH_X86);
    EXPECT_EQ(regMasker.count(), PERF_REG_X86_32_MAX);

    regMasker = GetSupportedRegMask(ArchType::ARCH_X86_64);
    // dont support PERF_REG_X86_DS,PERF_REG_X86_ES,PERF_REG_X86_FS,PERF_REG_X86_GS
    EXPECT_EQ(regMasker.count(), PERF_REG_X86_64_MAX - 4u);

    regMasker = GetSupportedRegMask(ArchType::ARCH_ARM);
    EXPECT_EQ(regMasker.count(), PERF_REG_ARM_MAX);

    regMasker = GetSupportedRegMask(ArchType::ARCH_ARM64);
    EXPECT_EQ(regMasker.count(), PERF_REG_ARM64_MAX);
}

/**
 * @tc.name: RegisterGetIP
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, RegisterGetIP, TestSize.Level1)
{
#if defined(target_cpu_x86_64)
    EXPECT_EQ(RegisterGetIP(ArchType::ARCH_X86_64), PERF_REG_X86_IP);
#elif defined(target_cpu_arm)
    EXPECT_EQ(RegisterGetIP(ArchType::ARCH_ARM), PERF_REG_ARM_PC);
#elif defined(target_cpu_arm64)
    EXPECT_EQ(RegisterGetIP(ArchType::ARCH_ARM64), PERF_REG_ARM64_PC);
#endif
}

/**
 * @tc.name: RegisterGetSP
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, RegisterGetSP, TestSize.Level1)
{
#if defined(target_cpu_x86_64)
    EXPECT_EQ(RegisterGetSP(ArchType::ARCH_X86_64), PERF_REG_X86_IP);
#elif defined(target_cpu_arm)
    EXPECT_EQ(RegisterGetSP(ArchType::ARCH_ARM), PERF_REG_ARM_SP);
#elif defined(target_cpu_arm64)
    EXPECT_EQ(RegisterGetSP(ArchType::ARCH_ARM64), PERF_REG_ARM64_SP);
#endif
}

/**
 * @tc.name: RegisterGetValue
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, RegisterGetValue, TestSize.Level1)
{
    uint64_t value = 0;
    const u64 registers[4] = {1, 2, 3, 4};

    EXPECT_EQ(RegisterGetValue(value, registers, 0, sizeof(registers)), true);
    EXPECT_EQ(RegisterGetValue(value, registers, sizeof(registers), sizeof(registers)), false);
    EXPECT_EQ(RegisterGetValue(value, registers, -1, sizeof(registers)), false);

    for (unsigned i = 0; i < sizeof(registers); i++) {
        RegisterGetValue(value, registers, i, sizeof(registers));
        EXPECT_EQ(value, registers[i]);
    }
}

/**
 * @tc.name: RegisterGetSPValue
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, RegisterGetSPValue, TestSize.Level1)
{
    uint64_t value = 0;
    uint64_t value2 = 0;
    u64 registers[PERF_REG_ARM64_MAX] = {1, 2, 3, 4};
    size_t sp = RegisterGetSP(buildArchType);
    registers[sp] = 0x1234;

    EXPECT_EQ(RegisterGetValue(value, registers, sp, sizeof(registers)),
              RegisterGetSPValue(value2, buildArchType, registers, sizeof(registers)));

    EXPECT_EQ(value, value2);
}

/**
 * @tc.name: RegisterGetIPValue
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, RegisterGetIPValue, TestSize.Level1)
{
    uint64_t value = 0;
    uint64_t value2 = 0;
    u64 registers[PERF_REG_ARM64_MAX] = {1, 2, 3, 4};
    size_t ip = RegisterGetIP(buildArchType);
    registers[ip] = 0x1234;

    EXPECT_EQ(RegisterGetValue(value, registers, ip, sizeof(registers)),
              RegisterGetIPValue(value2, buildArchType, registers, sizeof(registers)));

    EXPECT_EQ(value, value2);
}

/**
 * @tc.name: RegisterGetName
 * @tc.desc:
 * @tc.type: FUNC
 */
HWTEST_F(RegisterTest, RegisterGetName, TestSize.Level1)
{
    for (unsigned i = 0; i < PERF_REG_ARM64_MAX; i++) {
        EXPECT_EQ(RegisterGetName(i).empty(), false);
    }
}
} // namespace NativeDaemon
} // namespace Developtools
} // namespace OHOS
