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

#include "live_process_table.h"

namespace SysTuning {
namespace TraceStreamer {
namespace {
enum Index {
    TS = 0,
    DUR,
    CPU_TIME,
    PROCESS_ID,
    PROCESS_NAME,
    PARENT_PROCESS_ID,
    UID,
    USER_NAME,
    CPU_USAGE,
    PSS_INFO,
    THREAD_SUM,
    DISK_WRITES,
    DISK_READS
};
}
LiveProcessTable::LiveProcessTable(const TraceDataCache* dataCache) : TableBase(dataCache)
{
    tableColumn_.push_back(TableBase::ColumnInfo("ts", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("dur", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("cpu_time", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("process_id", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("process_name", "TEXT"));
    tableColumn_.push_back(TableBase::ColumnInfo("parent_process_id", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("uid", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("user_name", "TEXT"));
    tableColumn_.push_back(TableBase::ColumnInfo("cpu_usage", "REAL"));
    tableColumn_.push_back(TableBase::ColumnInfo("pss_info", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("thread_num", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("disk_writes", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("disk_reads", "INTEGER"));
    tablePriKey_.push_back("ts");
}

LiveProcessTable::~LiveProcessTable() {}

std::unique_ptr<TableBase::Cursor> LiveProcessTable::CreateCursor()
{
    return std::make_unique<Cursor>(dataCache_, this);
}

LiveProcessTable::Cursor::Cursor(const TraceDataCache* dataCache, TableBase* table)
    : TableBase::Cursor(dataCache, table, static_cast<uint32_t>(dataCache->GetConstLiveProcessData().Size())),
      liveProcessDetailDataObj_(dataCache->GetConstLiveProcessData())
{
}

LiveProcessTable::Cursor::~Cursor() {}

int LiveProcessTable::Cursor::Column(int column) const
{
    switch (column) {
        case TS: {
            sqlite3_result_int64(context_,
                                 static_cast<int64_t>(liveProcessDetailDataObj_.TimeStamData()[CurrentRow()]));
            break;
        }
        case DUR: {
            sqlite3_result_int64(context_, static_cast<int64_t>(liveProcessDetailDataObj_.Durs()[CurrentRow()]));
            break;
        }
        case CPU_TIME: {
            sqlite3_result_int64(context_, static_cast<int64_t>(liveProcessDetailDataObj_.CpuTimes()[CurrentRow()]));
            break;
        }
        case PROCESS_ID: {
            sqlite3_result_int(context_, static_cast<int32_t>(liveProcessDetailDataObj_.ProcessID()[CurrentRow()]));
            break;
        }
        case PROCESS_NAME: {
            sqlite3_result_text(context_, liveProcessDetailDataObj_.ProcessName()[CurrentRow()].c_str(),
                                STR_DEFAULT_LEN, nullptr);
            break;
        }
        case PARENT_PROCESS_ID: {
            sqlite3_result_int(context_,
                               static_cast<int32_t>(liveProcessDetailDataObj_.ParentProcessID()[CurrentRow()]));
            break;
        }
        case UID: {
            sqlite3_result_int(context_, static_cast<int32_t>(liveProcessDetailDataObj_.Uid()[CurrentRow()]));
            break;
        }
        case USER_NAME: {
            sqlite3_result_text(context_, liveProcessDetailDataObj_.UserName()[CurrentRow()].c_str(), STR_DEFAULT_LEN,
                                nullptr);
            break;
        }
        case CPU_USAGE: {
            sqlite3_result_double(context_, liveProcessDetailDataObj_.CpuUsage()[CurrentRow()]);
            break;
        }
        case PSS_INFO: {
            sqlite3_result_int(context_, static_cast<int32_t>(liveProcessDetailDataObj_.PssInfo()[CurrentRow()]));
            break;
        }
        case THREAD_SUM: {
            sqlite3_result_int(context_, static_cast<int32_t>(liveProcessDetailDataObj_.Threads()[CurrentRow()]));
            break;
        }
        case DISK_WRITES: {
            sqlite3_result_int(context_, static_cast<int32_t>(liveProcessDetailDataObj_.DiskWrites()[CurrentRow()]));
            break;
        }
        case DISK_READS: {
            sqlite3_result_int(context_, static_cast<int32_t>(liveProcessDetailDataObj_.DiskReads()[CurrentRow()]));
            break;
        }
        default:
            TS_LOGF("Unregistered column : %d", column);
            break;
    }
    return SQLITE_OK;
}
} // namespace TraceStreamer
} // namespace SysTuning
