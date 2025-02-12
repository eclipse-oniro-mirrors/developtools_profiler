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

#include "device_state_table.h"

namespace SysTuning {
namespace TraceStreamer {
namespace {
enum Index {
    ID = 0,
    BRIGHTNESS,
    BT_STATE,
    LOCATION,
    WIFI,
    STREAM_DEFAULT,
    VOICE_CALL,
    MUSIC,
    STREAM_RING,
    MEDIA,
    VOICE_ASSISTANT,
    SYSTEM,
    ALARM,
    NOTIFICATION,
    BT_SCO,
    ENFORCED_AUDIBLE,
    STREAM_DTMF,
    STREAM_TTS,
    ACCESSIBILITY,
    RECORDING,
    STREAM_ALL
};
}
DeviceStateTable::DeviceStateTable(const TraceDataCache* dataCache) : TableBase(dataCache)
{
    tableColumn_.push_back(TableBase::ColumnInfo("id", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("brightness", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("bt_state", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("location", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("wifi", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("stream_default", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("voice_call", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("music", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("stream_ring", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("media", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("voice_assistant", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("system", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("alarm", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("notification", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("bt_sco", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("enforced_audible", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("stream_dtmf", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("stream_tts", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("accessibility", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("recording", "INTEGER"));
    tableColumn_.push_back(TableBase::ColumnInfo("stream_all", "INTEGER"));
    tablePriKey_.push_back("id");
}

DeviceStateTable::~DeviceStateTable() {}

std::unique_ptr<TableBase::Cursor> DeviceStateTable::CreateCursor()
{
    return std::make_unique<Cursor>(dataCache_, this);
}

DeviceStateTable::Cursor::Cursor(const TraceDataCache* dataCache, TableBase* table)
    : TableBase::Cursor(dataCache, table, static_cast<uint32_t>(dataCache->GetConstDeviceStateData().Size())),
      deviceStateData_(dataCache->GetConstDeviceStateData())
{
}

DeviceStateTable::Cursor::~Cursor() {}

int DeviceStateTable::Cursor::Column(int column) const
{
    switch (column) {
        case ID:
            sqlite3_result_int64(context_, dataCache_->GetConstDeviceStateData().IdsData()[CurrentRow()]);
            break;
        case BRIGHTNESS:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Brightness()[CurrentRow()]);
            break;
        case BT_STATE:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().BtState()[CurrentRow()]);
            break;
        case LOCATION:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Location()[CurrentRow()]);
            break;
        case WIFI:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Wifi()[CurrentRow()]);
            break;
        case STREAM_DEFAULT:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().StreamDefault()[CurrentRow()]);
            break;
        case VOICE_CALL:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().VoiceCall()[CurrentRow()]);
            break;
        case MUSIC:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Music()[CurrentRow()]);
            break;
        case STREAM_RING:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().StreamRing()[CurrentRow()]);
            break;
        case MEDIA:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Media()[CurrentRow()]);
            break;
        case VOICE_ASSISTANT:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().VoiceAssistant()[CurrentRow()]);
            break;
        case SYSTEM:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().System()[CurrentRow()]);
            break;
        case ALARM:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Alarm()[CurrentRow()]);
            break;
        case NOTIFICATION:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Notification()[CurrentRow()]);
            break;
        case BT_SCO:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().BtSco()[CurrentRow()]);
            break;
        case ENFORCED_AUDIBLE:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().EnforcedAudible()[CurrentRow()]);
            break;
        case STREAM_DTMF:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().StreamDtmf()[CurrentRow()]);
            break;
        case STREAM_TTS:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().StreamTts()[CurrentRow()]);
            break;
        case ACCESSIBILITY:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Accessibility()[CurrentRow()]);
            break;
        case RECORDING:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().Recording()[CurrentRow()]);
            break;
        case STREAM_ALL:
            sqlite3_result_int(context_, dataCache_->GetConstDeviceStateData().StreamAll()[CurrentRow()]);
            break;
        default:
            TS_LOGF("Unregistered column : %d", column);
            break;
    }
    return SQLITE_OK;
}
} // namespace TraceStreamer
} // namespace SysTuning
