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

#ifndef HOOK_COMMON_H
#define HOOK_COMMON_H

#include "register.h"
#include "utilities.h"

#define MAX_THREAD_NAME (16)
#define MAX_UNWIND_DEPTH (30)

namespace OHOS {
namespace Developtools {
namespace NativeDaemon {
const int STACK_DATA_SIZE = 40000;
const int SPEED_UP_THRESHOLD = STACK_DATA_SIZE / 2;
const int SLOW_DOWN_THRESHOLD = STACK_DATA_SIZE / 4;
}
}
}

constexpr size_t kMaxRegSize = sizeof(uint64_t)
    * OHOS::Developtools::NativeDaemon::PERF_REG_ARM64_MAX;

enum {
    MALLOCDISABLE = (1u << 0),
    MMAPDISABLE = (1u << 1),
    FREEMSGSTACK = (1u << 2),
    MUNMAPMSGSTACK = (1u << 3),
    FPUNWIND = (1u << 4),
    BLOCKED = (1u << 5),
};

enum {
    MALLOC_MSG = 0,
    FREE_MSG,
    MMAP_MSG,
    MUNMAP_MSG,
    MEMORY_TAG,
    PR_SET_VMA_MSG,
};

typedef struct alignas(8) {
    union {
        char regs[kMaxRegSize];
        uint64_t ip[MAX_UNWIND_DEPTH + 1];
    };
    char tname[MAX_THREAD_NAME];
    struct timespec ts;
    void* addr;
    size_t mallocSize;
    uint32_t pid;
    uint32_t tid;
    uint32_t type;
} StackRawData;

typedef struct {
    uint32_t filterSize_;
    bool mallocDisable_;
    bool mmapDisable_;
    bool freeStackData_;
    bool munmapStackData_;
    uint8_t maxStackDepth_;
    bool fpunwind_;
    bool isBlocked;
} ClientConfig;

#endif // HOOK_SERVICE_H
