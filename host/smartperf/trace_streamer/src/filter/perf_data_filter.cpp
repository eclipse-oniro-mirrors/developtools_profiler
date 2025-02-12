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
#include "perf_data_filter.h"
#include "measure_filter.h"
#include "process_filter.h"
#include "slice_filter.h"
#include "string_to_numerical.h"
namespace SysTuning {
namespace TraceStreamer {
PerfDataFilter::PerfDataFilter(TraceDataCache* dataCache, const TraceStreamerFilters* filter)
    : FilterBase(dataCache, filter), fileIdToRowInFileTable_(INVALID_UINT64), fileIdToRowInChainTable_(INVALID_UINT64)
{
}
PerfDataFilter::~PerfDataFilter() = default;

size_t PerfDataFilter::AppendPerfFiles(uint64_t fileId, uint32_t serial, DataIndex symbols, DataIndex filePath)
{
    fileIds_.emplace(fileId);
    auto size = traceDataCache_->GetPerfFilesData()->AppendNewPerfFiles(fileId, serial, symbols, filePath);
    fileIdToRowInFileTable_.Insert(fileId, serial, size);
    if (!serial) {
        fileIdToRow_.insert(std::make_pair(fileId, size));
    }
    return size;
}

size_t PerfDataFilter::AppendPerfCallChain(uint64_t sampleId,
                                           uint64_t callChainId,
                                           uint64_t vaddrInFile,
                                           uint64_t fileId,
                                           uint64_t symbolId)
{
    auto size = traceDataCache_->GetPerfCallChainData()->AppendNewPerfCallChain(sampleId, callChainId, vaddrInFile,
                                                                                fileId, symbolId);
    fileIdToRowInChainTable_.Insert(fileId, symbolId, size);
    return size;
}
void PerfDataFilter::Finish()
{
    auto fileIds = traceDataCache_->GetPerfCallChainData()->FileIds();
    auto symbolsIds = traceDataCache_->GetPerfCallChainData()->SymbolIds();
    auto size = traceDataCache_->GetPerfCallChainData()->Size();
    auto filePath = traceDataCache_->GetPerfFilesData()->FilePaths();
    auto sambols = traceDataCache_->GetPerfFilesData()->Symbols();
    uint64_t flag = 1;
    flag = ~(flag << 63);
    for (auto i = 0; i < size; i++) {
        if (fileIds_.find(fileIds[i]) == fileIds_.end()) {
            // When the function name is empty and there is no file information to which the function belongs,
            // set the function name to the virtual address of the function in the file
            traceDataCache_->GetPerfCallChainData()->SetName(
                i, "+0x" + base::number(traceDataCache_->GetPerfCallChainData()->VaddrInFiles()[i] & flag));
            continue;
        }
        if (symbolsIds[i] == -1) {
            // When the function name is empty, if there has the file Id to which the function belongs,but the symboleid
            // is -1. Set the function name as "the file name of the function at the top of the callstack + the virtual
            // address of this function"
            auto pathIndex = filePath[fileIdToRow_.at(fileIds[i])];
            auto fullPath = traceDataCache_->GetDataFromDict(pathIndex);
            auto iPos = fullPath.find_last_of('/');
            fullPath = fullPath.substr(iPos + 1, -1);
            traceDataCache_->GetPerfCallChainData()->SetName(
                i, fullPath + "+0x" + base::number(traceDataCache_->GetPerfCallChainData()->VaddrInFiles()[i] & flag));
            continue;
        }
        // When the function name is empty, if there has the file Id to which the function belongs,and the symboleid
        // is not -1. Set the function name as the virtual address of this function
        auto value = fileIdToRowInFileTable_.Find(fileIds[i], symbolsIds[i]);
        if (value == INVALID_UINT64) {
            traceDataCache_->GetPerfCallChainData()->SetName(
                i, "+0x" + base::number(traceDataCache_->GetPerfCallChainData()->VaddrInFiles()[i] & flag));
            continue;
        }
        // The function name is not empty
        traceDataCache_->GetPerfCallChainData()->SetName(i, traceDataCache_->GetDataFromDict(sambols[value]));
    }
    fileIdToRowInFileTable_.Clear();
    fileIdToRowInChainTable_.Clear();
    fileIds_.clear();
    fileIdToRow_.clear();
}
} // namespace TraceStreamer
} // namespace SysTuning
