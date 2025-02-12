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
#include "pthread_semaphore.h"
#include <memory>
#include <ctime>

namespace {
constexpr int NS_PER_SEC = 1000 * 1000 * 1000;
}

PthreadSemaphore::PthreadSemaphore(unsigned int value) : value_(value)
{
    pthread_mutex_init(&mutex_, nullptr);
    pthread_cond_init(&cond_, nullptr);
}

PthreadSemaphore::~PthreadSemaphore()
{
    pthread_cond_destroy(&cond_);
    pthread_mutex_destroy(&mutex_);
}

bool PthreadSemaphore::Wait()
{
    pthread_mutex_lock(&mutex_);
    while (value_ == 0) {
        pthread_cond_wait(&cond_, &mutex_);
    }
    --value_;
    pthread_mutex_unlock(&mutex_);
    return true;
}

bool PthreadSemaphore::TryWait()
{
    pthread_mutex_lock(&mutex_);
    bool retval = TryWaitLocked();
    pthread_mutex_unlock(&mutex_);
    return retval;
}

bool PthreadSemaphore::TimedWait(int seconds, int nanoSeconds)
{
    pthread_mutex_lock(&mutex_);
    if (value_) {
        struct timespec ts = { 0, 0 };
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += seconds;
        ts.tv_nsec += nanoSeconds;
        ts.tv_sec += ts.tv_nsec / NS_PER_SEC;
        ts.tv_nsec %= NS_PER_SEC;
        pthread_cond_timedwait(&cond_, &mutex_, &ts);
    }
    bool retval = TryWaitLocked();
    pthread_mutex_unlock(&mutex_);
    return retval;
}

bool PthreadSemaphore::TryWaitLocked()
{
    if (value_ == 0) {
        return false;
    }
    --value_;
    return true;
}

bool PthreadSemaphore::Post()
{
    pthread_mutex_lock(&mutex_);
    ++value_;
    pthread_mutex_unlock(&mutex_);
    pthread_cond_broadcast(&cond_);
    return true;
}

unsigned int PthreadSemaphore::Value() const
{
    pthread_mutex_lock(&mutex_);
    unsigned int val = value_;
    pthread_mutex_unlock(&mutex_);
    return val;
}

SemaphorePtr PthreadSemaphoreFactory::Create(unsigned int value)
{
    return std::make_shared<PthreadSemaphore>(value);
}
