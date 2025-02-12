/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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

#ifndef WRITER_H
#define WRITER_H

#include <stddef.h>
#include "plugin_module_api.h"

class Writer {
public:
    virtual ~Writer() {}
    virtual long Write(const void* data, size_t size) = 0;
    virtual bool Flush() = 0;
    virtual void SetClockId(clockid_t clockId) {}

    virtual void UseMemory(int32_t size) {}

    virtual RandomWriteCtx* StartReport()
    {
        return nullptr;
    }
    virtual void FinishReport(int32_t size) {}

    virtual void ResetPos() {}
    virtual RandomWriteCtx* GetCtx()
    {
        return nullptr;
    }
};

#endif // !WRITER_H
