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
#ifndef HIPERF_VIRTUAL_RUNTIME_H
#define HIPERF_VIRTUAL_RUNTIME_H
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <functional>
#include <map>
#include "call_stack.h"
#include "perf_event_record.h"
#include "symbols_file.h"
#include "virtual_thread.h"

namespace OHOS {
namespace Developtools {
namespace NativeDaemon {
/*
This Class contains userspace thread objects. and kernel space objects
It represents a virtual operating environment, mainly referring to the relationship between pid,
mmaps, and symbols.

It mainly receives data is ip pointer (virtual address), pid
According to these data, it will find the corresponding mmap and its corresponding elf (also called
DSO)

Then find the corresponding symbol in the corresponding elf symbol file according to the offset
recorded in the corresponding mmap.
*/

class VirtualRuntime {
public:
    VirtualRuntime(bool onDevice = true);
    virtual ~VirtualRuntime();
    // thread need hook the record
    // from the record , it will call back to write some Simulated Record
    // case 1. some mmap will be create when it read mmaps for each new process (from record sample)

    // set symbols path , it will send to every symobile file for search
    bool SetSymbolsPaths(const std::vector<std::string> &symbolsPaths);

    // any mode
    static_assert(sizeof(pid_t) == sizeof(int));

    const std::set<std::unique_ptr<SymbolsFile>, CCompareSymbolsFile> &GetSymbolsFiles() const
    {
        return symbolsFiles_;
    }

    const Symbol GetSymbol(uint64_t ip, pid_t pid, pid_t tid,
                           const perf_callchain_context &context = PERF_CONTEXT_MAX);

    VirtualThread &GetThread(pid_t pid, pid_t tid);
    const std::map<pid_t, VirtualThread> &GetThreads() const
    {
        return userSpaceThreadMap_;
    }

    bool UnwindStack(std::vector<u64> regs,
                     const u8* stack_addr,
                     int stack_size,
                     pid_t pid,
                     pid_t tid,
                     std::vector<CallFrame>& callsFrames,
                     size_t maxStackLevel);
    bool GetSymbolName(pid_t pid, pid_t tid, std::vector<CallFrame>& callsFrames, int offset, bool first);
    void ClearMaps();
    // debug time
#ifdef HIPERF_DEBUG_TIME
    std::chrono::microseconds updateSymbolsTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindFromRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds unwindCallStackTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds symbolicRecordTimes_ = std::chrono::microseconds::zero();
    std::chrono::microseconds updateThreadTimes_ = std::chrono::microseconds::zero();
#endif
    const bool loadSymboleWhenNeeded_ = true; // thie is a feature config
    void UpdateSymbols(std::string filename);
    bool IsSymbolExist(std::string fileName);
    void UpdateMaps(pid_t pid, pid_t tid);
private:
    CallStack callstack_;
    // pid map with user space thread
    pthread_mutex_t threadMapsLock_;
    std::map<pid_t, VirtualThread> userSpaceThreadMap_;
    // not pid , just memmap
    std::vector<MemMapItem> kernelSpaceMemMaps_;
    pthread_mutex_t processSymbolsFileLock_;
    std::set<std::unique_ptr<SymbolsFile>, CCompareSymbolsFile> symbolsFiles_;
    enum SymbolCacheLimit : std::size_t {
        KERNEL_SYMBOL_CACHE_LIMIT = 4000,
        THREAD_SYMBOL_CACHE_LIMIT = 2000,
    };
    std::unordered_map<pid_t, HashList<uint64_t, Symbol>> threadSymbolCache_;
    HashList<uint64_t, Symbol> kernelSymbolCache_ {KERNEL_SYMBOL_CACHE_LIMIT};
    bool GetSymbolCache(uint64_t ip, pid_t pid, pid_t tid, Symbol &symbol,
                        const perf_callchain_context &context);
    void UpdateSymbolCache(uint64_t ip, Symbol &symbol, HashList<uint64_t, Symbol> &cache);

    // find synbols function name
    void MakeCallFrame(Symbol &symbol, CallFrame &callFrame);

    // threads
    VirtualThread &UpdateThread(pid_t pid, pid_t tid, const std::string name = "");
    std::string ReadThreadName(pid_t tid);
    VirtualThread &CreateThread(pid_t pid, pid_t tid);

    const Symbol GetKernelSymbol(uint64_t ip, const std::vector<MemMapItem> &memMaps,
                                 const VirtualThread &thread);
    const Symbol GetUserSymbol(uint64_t ip, const VirtualThread &thread);

    std::vector<std::string> symbolsPaths_;

    friend class VirtualRuntimeTest;
    friend class VirtualThread;
    pthread_mutex_t threadMemMapsLock_;
    std::vector<MemMapItem> processMemMaps_;
    std::unordered_set<uint64_t> failedIPs_;
};
} // namespace NativeDaemon
} // namespace Developtools
} // namespace OHOS
#endif