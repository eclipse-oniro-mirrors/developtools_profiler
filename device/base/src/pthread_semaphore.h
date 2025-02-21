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
#ifndef OHOS_PROFILER_PTHREAD_SEMAPHORE_H
#define OHOS_PROFILER_PTHREAD_SEMAPHORE_H


#include <pthread.h>
#include "i_semaphore.h"

class PthreadSemaphore : public ISemaphore {
public:
    explicit PthreadSemaphore(unsigned int value);
    ~PthreadSemaphore();

    bool Wait() override;
    bool TryWait() override;
    bool TimedWait(int seconds, int nanoSeconds) override;
    bool Post() override;
    unsigned int Value() const override;

private:
    bool TryWaitLocked();
    mutable pthread_mutex_t mutex_ {};
    mutable pthread_cond_t cond_ {};
    volatile unsigned int value_ = 0;
};

class PthreadSemaphoreFactory : public ISemaphoreFactory {
public:
    SemaphorePtr Create(unsigned int value) override;
};

#endif // OHOS_PROFILER_PTHREAD_SEMAPHORE_H