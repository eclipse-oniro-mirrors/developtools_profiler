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
#include "print_event_parser.h"
#include "stat_filter.h"
#include "string_to_numerical.h"
namespace SysTuning {
namespace TraceStreamer {
PrintEventParser::PrintEventParser(TraceDataCache* dataCache, const TraceStreamerFilters* filter)
    : EventParserBase(dataCache, filter),
      pointLength_(1),
      maxPointLength_(2)
{
}

bool PrintEventParser::ParsePrintEvent(const std::string& comm, uint64_t ts, uint32_t pid, std::string_view event)
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TRACING_MARK_WRITE, STAT_EVENT_RECEIVED);
    TracePoint point;
    if (GetTracePoint(event, point) != SUCCESS) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TRACING_MARK_WRITE, STAT_EVENT_DATA_INVALID);
        return false;
    }
    if (point.tgid_) {
        streamFilters_->processFilter_->GetOrCreateInternalPid(ts, point.tgid_);
    }
    uint32_t index = 0;
    switch (point.phase_) {
        case 'B': {
            index = streamFilters_->sliceFilter_->BeginSlice(comm, ts, pid, point.tgid_, INVALID_DATAINDEX,
                                                             traceDataCache_->GetDataIndex(point.name_));
            if (index != INVALID_UINT32) {
                // add distributed data
                traceDataCache_->GetInternalSlicesData()->SetDistributeInfo(
                    index, point.chainId_, point.spanId_, point.parentSpanId_, point.flag_, point.args_);
            } else {
                streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TRACING_MARK_WRITE, STAT_EVENT_DATA_LOST);
            }
            break;
        }
        case 'E': {
            streamFilters_->sliceFilter_->EndSlice(ts, pid, point.tgid_);
            break;
        }
        case 'S': {
            auto cookie = static_cast<uint64_t>(point.value_);
            streamFilters_->sliceFilter_->StartAsyncSlice(ts, pid, point.tgid_, cookie,
                traceDataCache_->GetDataIndex(point.name_));
            break;
        }
        case 'F': {
            auto cookie = static_cast<uint64_t>(point.value_);
            streamFilters_->sliceFilter_->FinishAsyncSlice(ts, pid, point.tgid_, cookie,
                traceDataCache_->GetDataIndex(point.name_));
            break;
        }
        case 'C': {
            DataIndex nameIndex = traceDataCache_->GetDataIndex(point.name_);
            uint32_t internalPid = streamFilters_->processFilter_->GetInternalPid(point.tgid_);
            if (internalPid != INVALID_ID) {
                streamFilters_->processMeasureFilter_->AppendNewMeasureData(internalPid, nameIndex, ts, point.value_);
            } else {
                streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TRACING_MARK_WRITE, STAT_EVENT_DATA_INVALID);
            }
            break;
        }
        default:
            TS_LOGD("point missing!");
            return false;
    }
    return true;
}

ParseResult PrintEventParser::CheckTracePoint(std::string_view pointStr) const
{
    if (pointStr.size() == 0) {
        TS_LOGD("get trace point data size is 0!");
        return ERROR;
    }

    std::string clockSyncSts = "trace_event_clock_sync";
    if (pointStr.compare(0, clockSyncSts.length(), clockSyncSts.c_str()) == 0) {
        TS_LOGD("skip trace point ：%s!", clockSyncSts.c_str());
        return ERROR;
    }

    if (pointStr.find_first_of('B') != 0 && pointStr.find_first_of('E') != 0 && pointStr.find_first_of('C') != 0 &&
        pointStr.find_first_of('S') != 0 && pointStr.find_first_of('F') != 0) {
        TS_LOGD("trace point not supported : [%c] !", pointStr[0]);
        return ERROR;
    }

    if (pointStr.find_first_of('E') != 0 && pointStr.size() == 1) {
        TS_LOGD("point string size error!");
        return ERROR;
    }

    if (pointStr.size() >= maxPointLength_) {
        if ((pointStr[1] != '|') && (pointStr[1] != '\n')) {
            TS_LOGD("not support data formart!");
            return ERROR;
        }
    }

    return SUCCESS;
}

std::string_view PrintEventParser::GetPointNameForBegin(std::string_view pointStr, size_t tGidlength) const
{
    size_t index = maxPointLength_ + tGidlength + pointLength_;

    size_t length = pointStr.size() - index - ((pointStr.back() == '\n') ? 1 : 0);
    std::string_view name = std::string_view(pointStr.data() + index, length);
    return name;
}

ParseResult PrintEventParser::HandlerB(std::string_view pointStr, TracePoint& outPoint, size_t tGidlength) const
{
    outPoint.name_ = GetPointNameForBegin(pointStr, tGidlength);
    if (outPoint.name_.empty()) {
        TS_LOGD("point name is empty!");
        return ERROR;
    }
    // Use $# to differentiate distributed data
    if (outPoint.name_.find("$#") == std::string::npos) {
        return SUCCESS;
    }
    // Resolve distributed calls
    // the normal data mybe like:
    // system-1298 ( 1298) [001] ...1 174330.287420: tracing_mark_write: B|1298|[8b00e96b2,2,1]:C$#decodeFrame$#"
    //    "{\"Process\":\"DecodeVideoFrame\",\"frameTimestamp\":37313484466} \
    //        system - 1298(1298)[001]... 1 174330.287622 : tracing_mark_write : E | 1298 \n
    const std::regex distributeMatcher =
        std::regex(R"((?:^\[([a-z0-9]+),(\d+),(\d+)\]:?([CS]?)\$#)?(.*)\$#(.*)$)");
    std::smatch matcheLine;
    bool matched = std::regex_match(outPoint.name_, matcheLine, distributeMatcher);
    if (matched) {
        size_t index = 0;
        outPoint.chainId_ = matcheLine[++index].str();
        outPoint.spanId_ = matcheLine[++index].str();
        outPoint.parentSpanId_ = matcheLine[++index].str();
        outPoint.flag_ = matcheLine[++index].str();
        outPoint.name_ = matcheLine[++index].str();
        outPoint.args_ = matcheLine[++index].str();
    }
    return SUCCESS;
}

ParseResult PrintEventParser::HandlerE(void)
{
    return SUCCESS;
}

size_t PrintEventParser::GetNameLength(std::string_view pointStr, size_t nameIndex)
{
    size_t namelength = 0;
    for (size_t i = nameIndex; i < pointStr.size(); i++) {
        if (pointStr[i] == ' ') {
            namelength = i - nameIndex;
        }
        if (pointStr[i] == '|') {
            namelength = i - nameIndex;
            break;
        }
    }
    return namelength;
}

size_t PrintEventParser::GetValueLength(std::string_view pointStr, size_t valueIndex) const
{
    size_t valuePipe = pointStr.find('|', valueIndex);
    size_t valueLen = pointStr.size() - valueIndex;
    if (valuePipe != std::string_view::npos) {
        valueLen = valuePipe - valueIndex;
    }

    if (valueLen == 0) {
        return 0;
    }

    if (pointStr[valueIndex + valueLen - pointLength_] == '\n') {
        valueLen--;
    }

    return valueLen;
}

ParseResult PrintEventParser::HandlerCSF(std::string_view pointStr, TracePoint& outPoint, size_t tGidlength) const
{
    // point name
    size_t nameIndex = maxPointLength_ + tGidlength + pointLength_;
    size_t namelength = GetNameLength(pointStr, nameIndex);
    if (namelength == 0) {
        TS_LOGD("point name length is error!");
        return ERROR;
    }
    outPoint.name_ = std::string_view(pointStr.data() + nameIndex, namelength);

    // point value
    size_t valueIndex = nameIndex + namelength + pointLength_;
    size_t valueLen = GetValueLength(pointStr, valueIndex);
    if (valueLen == 0) {
        TS_LOGD("point value length is error!");
        return ERROR;
    }

    std::string valueStr(pointStr.data() + valueIndex, valueLen);
    if (!base::StrToUInt64(valueStr).has_value()) {
        TS_LOGD("point value is error!");
        return ERROR;
    }
    outPoint.value_ = base::StrToUInt64(valueStr).value();

    size_t valuePipe = pointStr.find('|', valueIndex);
    if (valuePipe != std::string_view::npos) {
        size_t groupLen = pointStr.size() - valuePipe - pointLength_;
        if (groupLen == 0) {
            return ERROR;
        }

        if (pointStr[pointStr.size() - pointLength_] == '\n') {
            groupLen--;
        }

        outPoint.categoryGroup_ = std::string_view(pointStr.data() + valuePipe + 1, groupLen);
    }

    return SUCCESS;
}

ParseResult PrintEventParser::GetTracePoint(std::string_view pointStr, TracePoint& outPoint) const
{
    if (CheckTracePoint(pointStr) != SUCCESS) {
        return ERROR;
    }

    size_t tGidlength = 0;
    // we may get wrong format data like tracing_mark_write: E
    // while the format data must be E|call-tid
    // please use a regular-format to get all the data
    outPoint.phase_ = pointStr.front();
    outPoint.tgid_ = GetThreadGroupId(pointStr, tGidlength);

    ParseResult ret = ERROR;
    switch (outPoint.phase_) {
        case 'B': {
            ret = HandlerB(pointStr, outPoint, tGidlength);
            break;
        }
        case 'E': {
            ret = HandlerE();
            break;
        }
        case 'S':
        case 'F':
        case 'C': {
            ret = HandlerCSF(pointStr, outPoint, tGidlength);
            break;
        }
        default:
            return ERROR;
    }
    return ret;
}

uint32_t PrintEventParser::GetThreadGroupId(std::string_view pointStr, size_t& length) const
{
    for (size_t i = maxPointLength_; i < pointStr.size(); i++) {
        if (pointStr[i] == '|' || pointStr[i] == '\n') {
            break;
        }

        if (pointStr[i] < '0' || pointStr[i] > '9') {
            return ERROR;
        }

        length++;
    }

    std::string str(pointStr.data() + maxPointLength_, length);
    return base::StrToUInt32(str).value_or(0);
}
} // namespace TraceStreamer
} // namespace SysTuning
