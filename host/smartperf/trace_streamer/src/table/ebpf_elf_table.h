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
#ifndef EBPF_ELF_TABLE_H
#define EBPF_ELF_TABLE_H

#include "table_base.h"
#include "trace_stdtype.h"

namespace SysTuning {
namespace TraceStreamer {
class EbpfElfTable : public TableBase {
public:
    explicit EbpfElfTable(const TraceDataCache* dataCache);
    ~EbpfElfTable() override;
    std::unique_ptr<TableBase::Cursor> CreateCursor() override;

private:
    void EstimateFilterCost(FilterConstraints& fc, EstimatedIndexInfo& ei) override;
    // filter out by operator[=, >, <...] from column(ID)
    bool CanFilterId(const char op, size_t& rowCount);
    void FilterByConstraint(FilterConstraints& fc, double& filterCost, size_t rowCount);

    class Cursor : public TableBase::Cursor {
    public:
        explicit Cursor(const TraceDataCache* dataCache, TableBase* table);
        ~Cursor() override;
        int Filter(const FilterConstraints& fc, sqlite3_value** argv) override;
        int Column(int column) const override;

        void FilterId(unsigned char op, sqlite3_value* argv);

    private:
        const EbpfElf& ebpfElfObj_;
    };
};
} // namespace TraceStreamer
} // namespace SysTuning
#endif // EBPF_ELF_TABLE_H
