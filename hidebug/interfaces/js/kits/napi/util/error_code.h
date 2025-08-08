/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ERROR_CODE_H
#define ERROR_CODE_H
enum ErrorCode {
    PERMISSION_ERROR = 201,
    PARAMETER_ERROR = 401,
    VERSION_ERROR = 801,
    SYSTEM_ABILITY_NOT_FOUND = 11400101,
    HAVA_ALREADY_TRACE = 11400102,
    WITHOUT_WRITE_PERMISSON = 11400103,
    SYSTEM_STATUS_ABNORMAL = 11400104,
    NO_CAPTURE_TRACE_RUNNING = 11400105,
};

enum DumpRawHeapErrors {
    QUOTA_EXCEEDED = 11400106,
    FORK_FAILED = 11400107,
    FAILED_WAIT_CHILD_PROCESS_FINISHED = 11400108,
    TIMEOUT_WAIT_CHILD_PROCESS_FINISHED = 11400109,
    LOW_DISK_SPACE = 11400110,
    NAPI_INTERFACE_ERROR = 11400111,
    REPEAT_DUMPING = 11400112,
    FAILED_CREATE_FILE = 11400113,
};

#endif //ERROR_CODE_H
