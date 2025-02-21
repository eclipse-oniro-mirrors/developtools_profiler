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
#include "stack_preprocess.h"

#include <unistd.h>

#include "logging.h"
#include "plugin_service_types.pb.h"

static std::atomic<uint64_t> timeCost = 0;
static std::atomic<uint64_t> unwindTimes = 0;

constexpr static uint32_t MAX_BUFFER_SIZE = 50 * 1024;
constexpr static uint32_t MAX_MATCH_CNT = 1000;
constexpr static uint32_t MAX_MATCH_INTERVAL = 2000;
constexpr static uint32_t LOG_PRINT_TIMES = 10000;
constexpr static uint32_t FUNCTION_MAP_LOG_PRINT = 100;
constexpr static uint32_t FILE_MAP_LOG_PRINT = 10;
constexpr static uint32_t MAX_BATCH_CNT = 5;

using namespace OHOS::Developtools::NativeDaemon;

StackPreprocess::StackPreprocess(const StackDataRepeaterPtr& dataRepeater, NativeHookConfig hookConfig)
    : dataRepeater_(dataRepeater), buffer_(new (std::nothrow) uint8_t[MAX_BUFFER_SIZE]),
      hookConfig_(hookConfig), fpHookData_(nullptr, nullptr)
{
    runtime_instance = std::make_shared<VirtualRuntime>();

    if (hookConfig_.malloc_free_matching_interval() > MAX_MATCH_INTERVAL) {
        HILOG_INFO(LOG_CORE, "Not support set %d", hookConfig_.malloc_free_matching_interval());
        hookConfig_.set_malloc_free_matching_interval(MAX_MATCH_INTERVAL);
    }

    if (hookConfig_.malloc_free_matching_cnt() > MAX_MATCH_CNT) {
        HILOG_INFO(LOG_CORE, "Not support set %d", hookConfig_.malloc_free_matching_cnt());
        hookConfig_.set_malloc_free_matching_cnt(MAX_MATCH_CNT);
    }
    HILOG_INFO(LOG_CORE, "malloc_free_matching_interval = %d malloc_free_matching_cnt = %d\n",
        hookConfig_.malloc_free_matching_interval(), hookConfig_.malloc_free_matching_cnt());
    // create file
    if (hookConfig_.save_file()) {
        if (hookConfig_.file_name() != "") {
            HILOG_DEBUG(LOG_CORE, "save file name = %s", hookConfig_.file_name().c_str());
            FILE *fp = fopen(hookConfig_.file_name().c_str(), "wb+");
            if (fp) {
                fpHookData_.reset();
                fpHookData_ = std::unique_ptr<FILE, decltype(&fclose)>(fp, fclose);
            } else {
                fpHookData_.reset();
            }
        } else {
            HILOG_WARN(LOG_CORE, "If you need to save the file, please set the file_name");
        }
    }
}

StackPreprocess::~StackPreprocess()
{
    isStopTakeData_ = true;
    if (dataRepeater_) {
        dataRepeater_->Close();
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    runtime_instance = nullptr;
    fpHookData_ = nullptr;
}

void StackPreprocess::SetWriter(const std::shared_ptr<BufferWriter>& writer)
{
    writer_ = writer;
}

bool StackPreprocess::StartTakeResults()
{
    CHECK_NOTNULL(dataRepeater_, false, "data repeater null");

    std::thread demuxer(&StackPreprocess::TakeResults, this);
    CHECK_TRUE(demuxer.get_id() != std::thread::id(), false, "demuxer thread invalid");

    thread_ = std::move(demuxer);
    isStopTakeData_ = false;
    return true;
}

bool StackPreprocess::StopTakeResults()
{
    HILOG_INFO(LOG_CORE, "start StopTakeResults");
    CHECK_NOTNULL(dataRepeater_, false, "data repeater null");
    CHECK_TRUE(thread_.get_id() != std::thread::id(), false, "thread invalid");

    isStopTakeData_ = true;
    dataRepeater_->PutRawStack(nullptr);
    HILOG_INFO(LOG_CORE, "Wait thread join");

    if (thread_.joinable()) {
        thread_.join();
    }
    HILOG_INFO(LOG_CORE, "Wait thread join success");
    return true;
}

void StackPreprocess::TakeResults()
{
    if (!dataRepeater_) {
        return;
    }

    size_t minStackDepth = hookConfig_.max_stack_depth() > MIN_STACK_DEPTH
        ? MIN_STACK_DEPTH : hookConfig_.max_stack_depth();
    if (hookConfig_.blocked()) {
        minStackDepth = static_cast<size_t>(hookConfig_.max_stack_depth());
    }
    minStackDepth += FILTER_STACK_DEPTH;
    HILOG_INFO(LOG_CORE, "TakeResults thread %d, start!", gettid());
    while (1) {
        BatchNativeHookData stackData;
        RawStackPtr batchRawStack[MAX_BATCH_CNT] = {nullptr};
        auto result = dataRepeater_->TakeRawData(hookConfig_.malloc_free_matching_interval(),
            MAX_BATCH_CNT, batchRawStack);
        if (!result || isStopTakeData_) {
            break;
        }
        for (unsigned int i = 0; i < MAX_BATCH_CNT; i++) {
            auto rawData = batchRawStack[i];
            if (!rawData || isStopTakeData_) {
                break;
            }

            if (!rawData->reportFlag) {
                ignoreCnts_++;
                if (ignoreCnts_ % LOG_PRINT_TIMES == 0) {
                    HILOG_INFO(LOG_CORE, "ignoreCnts_ = %d quene size = %zu\n", ignoreCnts_, dataRepeater_->Size());
                }
                continue;
            }
            eventCnts_++;
            if (eventCnts_ % LOG_PRINT_TIMES == 0) {
                HILOG_INFO(LOG_CORE, "eventCnts_ = %d quene size = %zu\n", eventCnts_, dataRepeater_->Size());
            }

            std::vector<u64> u64regs;
            std::vector<CallFrame> callsFrames;

            if (hookConfig_.fp_unwind()) {
                for (int idx = 1; idx < MAX_UNWIND_DEPTH + 1; ++idx) {
                    if (rawData->stackConext.ip[idx] == 0) {
                        break;
                    }
                    OHOS::Developtools::NativeDaemon::CallFrame frame(0);
                    frame.ip_ = rawData->stackConext.ip[idx];
                    callsFrames.push_back(frame);
                }
            } else {
                int regCount = OHOS::Developtools::NativeDaemon::RegisterGetCount();
#if defined(__arm__)
                uint32_t *regAddrArm = reinterpret_cast<uint32_t *>(rawData->stackConext.regs);
                for (int idx = 0; idx < regCount; ++idx) {
                    u64regs.push_back(*regAddrArm++);
                }
#else
                uint64_t *regAddrAarch64 = reinterpret_cast<uint64_t *>(rawData->stackConext.regs);
                for (int idx = 0; idx < regCount; ++idx) {
                    u64regs.push_back(*regAddrAarch64++);
                }
#endif
            }
#ifdef PERFORMANCE_DEBUG
            struct timespec start = {};
            clock_gettime(CLOCK_REALTIME, &start);
#endif
            size_t stackDepth = (hookConfig_.max_stack_depth() > 0)
                        ? hookConfig_.max_stack_depth() + FILTER_STACK_DEPTH
                        : MAX_CALL_FRAME_UNWIND_SIZE;
            if (rawData->reduceStackFlag) {
                stackDepth = minStackDepth;
            }
            bool ret = runtime_instance->UnwindStack(u64regs, rawData->stackData.get(), rawData->stackSize,
                rawData->stackConext.pid, rawData->stackConext.tid, callsFrames,
                stackDepth);
            if (!ret) {
                HILOG_ERROR(LOG_CORE, "unwind fatal error");
                continue;
            }
            if (rawData->stackConext.type == MMAP_MSG) {
                // if mmap msg trigger by dlopen, update maps voluntarily
                for (auto &callsFrame : callsFrames) {
                    if (callsFrame.symbolName_ == "dlopen") {
                        HILOG_INFO(LOG_CORE, "mmap msg trigger by dlopen, update maps voluntarily");
                        runtime_instance->UpdateMaps(rawData->stackConext.pid, rawData->stackConext.tid);
                        break;
                    }
                }
            }
#ifdef PERFORMANCE_DEBUG
            struct timespec end = {};
            clock_gettime(CLOCK_REALTIME, &end);
            timeCost += (end.tv_sec - start.tv_sec) * MAX_MATCH_CNT * MAX_MATCH_CNT * MAX_MATCH_CNT +
                (end.tv_nsec - start.tv_nsec);
            unwindTimes++;
            if (unwindTimes % LOG_PRINT_TIMES == 0) {
                HILOG_ERROR(LOG_CORE, "unwindTimes %" PRIu64" cost time = %" PRIu64" mean cost = %" PRIu64"\n",
                    unwindTimes.load(), timeCost.load(), timeCost.load() / unwindTimes.load());
            }
#endif
            if (hookConfig_.save_file() && hookConfig_.file_name() != "") {
                writeFrames(rawData, callsFrames);
            } else if (!hookConfig_.save_file()) {
                SetHookData(rawData, callsFrames, stackData);
            }
        }
        if (stackData.events().size() > 0) {
            size_t length = stackData.ByteSizeLong();
            if (length < MAX_BUFFER_SIZE) {
                stackData.SerializeToArray(buffer_.get(), length);
                ProfilerPluginData pluginData;
                pluginData.set_name("nativehook");
                pluginData.set_version("1.01");
                pluginData.set_status(0);
                pluginData.set_data(buffer_.get(), length);
                struct timespec ts;
                clock_gettime(CLOCK_REALTIME, &ts);
                pluginData.set_clock_id(ProfilerPluginData::CLOCKID_REALTIME);
                pluginData.set_tv_sec(ts.tv_sec);
                pluginData.set_tv_nsec(ts.tv_nsec);
                writer_->WriteMessage(pluginData, "nativehook");
                writer_->Flush();
            }
        }
    }
    HILOG_INFO(LOG_CORE, "TakeResults thread %d, exit!", gettid());
}

void StackPreprocess::SetHookData(RawStackPtr rawStack,
    std::vector<CallFrame>& callsFrames, BatchNativeHookData& batchNativeHookData)
{
        NativeHookData* hookData = batchNativeHookData.add_events();
        hookData->set_tv_sec(rawStack->stackConext.ts.tv_sec);
        hookData->set_tv_nsec(rawStack->stackConext.ts.tv_nsec);
        // ignore the first two frame if dwarf unwind
        size_t idx = hookConfig_.fp_unwind() ? 0 : FILTER_STACK_DEPTH;

        if (rawStack->stackConext.type == MALLOC_MSG) {
            AllocEvent* allocEvent = hookData->mutable_alloc_event();
            allocEvent->set_pid(rawStack->stackConext.pid);
            allocEvent->set_tid(rawStack->stackConext.tid);
            allocEvent->set_addr((uint64_t)rawStack->stackConext.addr);
            allocEvent->set_size(static_cast<uint64_t>(rawStack->stackConext.mallocSize));
            std::string name = rawStack->stackConext.tname;
            if (!name.empty()) {
                allocEvent->set_thread_name_id(GetThreadIdx(name, batchNativeHookData));
            }
            for (; idx < callsFrames.size(); ++idx) {
                Frame* frame = allocEvent->add_frame_info();
                SetFrameInfo(*frame, callsFrames[idx], batchNativeHookData);
            }
        } else if (rawStack->stackConext.type == FREE_MSG) {
            FreeEvent* freeEvent = hookData->mutable_free_event();
            freeEvent->set_pid(rawStack->stackConext.pid);
            freeEvent->set_tid(rawStack->stackConext.tid);
            freeEvent->set_addr((uint64_t)rawStack->stackConext.addr);
            std::string name = rawStack->stackConext.tname;
            if (!name.empty()) {
                freeEvent->set_thread_name_id(GetThreadIdx(name, batchNativeHookData));
            }
            for (; idx < callsFrames.size(); ++idx) {
                Frame* frame = freeEvent->add_frame_info();
                SetFrameInfo(*frame, callsFrames[idx], batchNativeHookData);
            }
        } else if (rawStack->stackConext.type == MMAP_MSG) {
            MmapEvent* mmapEvent = hookData->mutable_mmap_event();
            mmapEvent->set_pid(rawStack->stackConext.pid);
            mmapEvent->set_tid(rawStack->stackConext.tid);
            mmapEvent->set_addr((uint64_t)rawStack->stackConext.addr);
            mmapEvent->set_size(static_cast<uint64_t>(rawStack->stackConext.mallocSize));
            std::string name = rawStack->stackConext.tname;
            if (!name.empty()) {
                mmapEvent->set_thread_name_id(GetThreadIdx(name, batchNativeHookData));
            }
            for (; idx < callsFrames.size(); ++idx) {
                Frame* frame = mmapEvent->add_frame_info();
                SetFrameInfo(*frame, callsFrames[idx], batchNativeHookData);
            }
        } else if (rawStack->stackConext.type == MUNMAP_MSG) {
            MunmapEvent* munmapEvent = hookData->mutable_munmap_event();
            munmapEvent->set_pid(rawStack->stackConext.pid);
            munmapEvent->set_tid(rawStack->stackConext.tid);
            munmapEvent->set_addr((uint64_t)rawStack->stackConext.addr);
            munmapEvent->set_size(static_cast<uint64_t>(rawStack->stackConext.mallocSize));
            std::string name = rawStack->stackConext.tname;
            if (!name.empty()) {
                munmapEvent->set_thread_name_id(GetThreadIdx(name, batchNativeHookData));
            }
            for (; idx < callsFrames.size(); ++idx) {
                Frame* frame = munmapEvent->add_frame_info();
                SetFrameInfo(*frame, callsFrames[idx], batchNativeHookData);
            }
        } else if (rawStack->stackConext.type == MEMORY_TAG) {
            MemTagEvent* tagEvent = hookData->mutable_tag_event();
            tagEvent->set_tag(rawStack->stackConext.tname);
            tagEvent->set_size(rawStack->stackConext.mallocSize);
            tagEvent->set_addr((uint64_t)rawStack->stackConext.addr);
        }
}

uint32_t StackPreprocess::GetThreadIdx(std::string threadName, BatchNativeHookData& batchNativeHookData)
{
    auto it = threadMap_.find(threadName);
    if (it != threadMap_.end()) {
        return it->second;
    } else {
        auto hookData = batchNativeHookData.add_events();
        auto* thread = hookData->mutable_thread_name_map();
        thread->set_id(threadMap_.size() + 1);
        thread->set_name(threadName);
        threadMap_.insert(std::pair<std::string, uint32_t>(threadName, threadMap_.size() + 1));

        HILOG_INFO(LOG_CORE, "threadName = %s, functionMap_.size() = %zu\n", threadName.c_str(), threadMap_.size());
        return threadMap_.size();
    }
}

void StackPreprocess::writeFrames(RawStackPtr rawStack, const std::vector<CallFrame>& callsFrames)
{
    CHECK_TRUE(fpHookData_.get() != nullptr, NO_RETVAL, "fpHookData_ is nullptr, please check file_name(%s)",
        hookConfig_.file_name().c_str());
    if (rawStack->stackConext.type == MEMORY_TAG) {
        fprintf(fpHookData_.get(), "memtag;%u;%u;%" PRId64 ";%ld;0x%" PRIx64 ":tag:%s\n",
            rawStack->stackConext.pid, rawStack->stackConext.tid,
            (int64_t)rawStack->stackConext.ts.tv_sec, rawStack->stackConext.ts.tv_nsec,
            (uint64_t)rawStack->stackConext.addr, rawStack->stackConext.tname);
        return;
    }
    std::string tag = "";
    switch (rawStack->stackConext.type) {
        case FREE_MSG:
            tag = "free";
            break;
        case MALLOC_MSG:
            tag = "malloc";
            break;
        case MMAP_MSG:
            tag = "mmap";
            break;
        case MUNMAP_MSG:
            tag = "munmap";
            break;
        default:
            break;
    }

    fprintf(fpHookData_.get(), "%s;%u;%u;%" PRId64 ";%ld;0x%" PRIx64 ";%zu\n", tag.c_str(),
        rawStack->stackConext.pid, rawStack->stackConext.tid, (int64_t)rawStack->stackConext.ts.tv_sec,
        rawStack->stackConext.ts.tv_nsec, (uint64_t)rawStack->stackConext.addr, rawStack->stackConext.mallocSize);

    for (size_t idx = 0; idx < callsFrames.size(); ++idx) {
        (void)fprintf(fpHookData_.get(), "0x%" PRIx64 ";0x%" PRIx64 ";%s;%s;0x%" PRIx64 ";%" PRIu64 "\n",
            callsFrames[idx].ip_, callsFrames[idx].sp_, std::string(callsFrames[idx].symbolName_).c_str(),
            std::string(callsFrames[idx].filePath_).c_str(), callsFrames[idx].offset_, callsFrames[idx].symbolOffset_);
    }
}

void StackPreprocess::SetFrameInfo(Frame& frame, CallFrame& callsFrame, BatchNativeHookData& batchNativeHookData)
{
    frame.set_ip(callsFrame.ip_);
    frame.set_sp(callsFrame.sp_);
    frame.set_offset(callsFrame.offset_);
    frame.set_symbol_offset(callsFrame.symbolOffset_);
    if (hookConfig_.string_compressed()) {
        auto itFuntion = functionMap_.find(std::string(callsFrame.symbolName_));
        if (itFuntion != functionMap_.end()) {
            frame.set_symbol_name_id(itFuntion->second);
        } else {
            frame.set_symbol_name_id(functionMap_.size() + 1);
            auto hookData = batchNativeHookData.add_events();
            SymbolMap* symbolMap = hookData->mutable_symbol_name();
            symbolMap->set_id(functionMap_.size() + 1);
            symbolMap->set_name(std::string(callsFrame.symbolName_));
            functionMap_.insert(std::pair<std::string, uint32_t>(callsFrame.symbolName_, functionMap_.size() + 1));
            if (functionMap_.size() % FUNCTION_MAP_LOG_PRINT == 0) {
                HILOG_INFO(LOG_CORE, "functionMap_.size() = %zu\n", functionMap_.size());
            }
        }

        auto itFile = fileMap_.find(std::string(callsFrame.filePath_));
        if (itFile != fileMap_.end()) {
            frame.set_file_path_id(itFile->second);
        } else {
            frame.set_file_path_id(fileMap_.size() + 1);
            auto hookData = batchNativeHookData.add_events();
            FilePathMap* filepathMap = hookData->mutable_file_path();
            filepathMap->set_id(fileMap_.size() + 1);
            filepathMap->set_name(std::string(callsFrame.filePath_));
            fileMap_.insert(std::pair<std::string, uint32_t>(callsFrame.filePath_, fileMap_.size() + 1));
            if (fileMap_.size() % FILE_MAP_LOG_PRINT == 0) {
                HILOG_INFO(LOG_CORE, "fileMap.size() = %zu\n", fileMap_.size());
            }
        }
    } else {
        frame.set_symbol_name(std::string(callsFrame.symbolName_));
        frame.set_file_path(std::string(callsFrame.filePath_));
    }
}
