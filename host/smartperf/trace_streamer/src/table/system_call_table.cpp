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

#include "system_call_table.h"

namespace SysTuning {
namespace TraceStreamer {
namespace {
enum Index { SYSCALL_NUM = 0, TYPE, IPID, TS, RET };
}
SystemCallTable::SystemCallTable(const TraceDataCache* dataCache) : TableBase(dataCache)
{
    tableColumn_.push_back(TableBase::ColumnInfo("syscall_num", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("type", "TEXT"));
    tableColumn_.push_back(TableBase::ColumnInfo("ipid", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("ts", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("ret", "INTEGER"));
    tablePriKey_.push_back("syscall_num");
}

SystemCallTable::~SystemCallTable() {}

std::unique_ptr<TableBase::Cursor> SystemCallTable::CreateCursor()
{
    return std::make_unique<Cursor>(dataCache_, this);
}

SystemCallTable::Cursor::Cursor(const TraceDataCache* dataCache, TableBase* table)
    : TableBase::Cursor(dataCache, table, static_cast<uint32_t>(dataCache->GetConstSysCallData().Size())),
      sysCallObj_(dataCache->GetConstSysCallData())
{
}

SystemCallTable::Cursor::~Cursor() {}

int SystemCallTable::Cursor::Column(int column) const
{
    switch (column) {
        case SYSCALL_NUM:
            sqlite3_result_int64(context_, dataCache_->GetConstSysCallData().SysCallsData()[CurrentRow()]);
            break;
        case TYPE:
            sqlite3_result_text(context_, dataCache_->GetDataFromDict(sysCallObj_.TypesData()[CurrentRow()]).c_str(),
                                STR_DEFAULT_LEN, nullptr);
            break;
        case IPID:
            sqlite3_result_int64(context_, dataCache_->GetConstSysCallData().IpidsData()[CurrentRow()]);
            break;
        case TS:
            sqlite3_result_int64(context_, dataCache_->GetConstSysCallData().TimeStamData()[CurrentRow()]);
            break;
        case RET:
            sqlite3_result_int64(context_, dataCache_->GetConstSysCallData().RetsData()[CurrentRow()]);
            break;
        default:
            TS_LOGF("Unregistered column : %d", column);
            break;
    }
    return SQLITE_OK;
}
} // namespace TraceStreamer
} // namespace SysTuning
