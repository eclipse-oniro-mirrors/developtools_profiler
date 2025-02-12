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

#include "htrace_parser.h"
#include <unistd.h>
#include "binder_filter.h"
#include "cpu_filter.h"
#include "ftrace_event.pb.h"
#include "log.h"
#include "memory_plugin_result.pb.h"
#include "services/common_types.pb.h"
#include "stat_filter.h"
#include "trace_plugin_result.pb.h"
#if IS_WASM
#include "../rpc/wasm_func.h"
#endif
namespace SysTuning {
namespace TraceStreamer {
HtraceParser::HtraceParser(TraceDataCache* dataCache, const TraceStreamerFilters* filters)
    : ParserBase(filters),
      traceDataCache_(dataCache),
      htraceCpuDetailParser_(std::make_unique<HtraceCpuDetailParser>(dataCache, filters)),
      htraceSymbolsDetailParser_(std::make_unique<HtraceSymbolsDetailParser>(dataCache, filters)),
      htraceMemParser_(std::make_unique<HtraceMemParser>(dataCache, filters)),
      htraceClockDetailParser_(std::make_unique<HtraceClockDetailParser>(dataCache, filters)),
      htraceHiLogParser_(std::make_unique<HtraceHiLogParser>(dataCache, filters)),
      htraceNativeHookParser_(std::make_unique<HtraceNativeHookParser>(dataCache, filters)),
      htraceHidumpParser_(std::make_unique<HtraceHidumpParser>(dataCache, filters)),
      cpuUsageParser_(std::make_unique<HtraceCpuDataParser>(dataCache, filters)),
      networkParser_(std::make_unique<HtraceNetworkParser>(dataCache, filters)),
      diskIOParser_(std::make_unique<HtraceDiskIOParser>(dataCache, filters)),
      processParser_(std::make_unique<HtraceProcessParser>(dataCache, filters)),
      ebpfDataParser_(std::make_unique<EbpfDataParser>(dataCache, filters)),
      hisyseventParser_(std::make_unique<HtraceHisyseventParser>(dataCache, filters))
{
#if WITH_PERF
      perfDataParser_ = std::make_unique<PerfDataParser>(dataCache, filters);
#endif
#ifdef SUPPORTTHREAD
    supportThread_ = true;
    dataSegArray_ = std::make_unique<HtraceDataSegment[]>(MAX_SEG_ARRAY_SIZE);
#else
    dataSegArray_ = std::make_unique<HtraceDataSegment[]>(1);
#endif
}

HtraceParser::~HtraceParser()
{
    TS_LOGI("clockid 2 is for RealTime and 1 is for BootTime");
}

void HtraceParser::WaitForParserEnd()
{
    if (parseThreadStarted_ || filterThreadStarted_) {
        toExit_ = true;
        while (!exited_) {
            usleep(sleepDur_ * sleepDur_);
        }
    }
    htraceCpuDetailParser_->FilterAllEvents();
    htraceNativeHookParser_->FinishParseNativeHookData();
    htraceHiLogParser_->Finish();
    htraceMemParser_->Finish();
    htraceNativeHookParser_->Finish();
    htraceHidumpParser_->Finish();
    cpuUsageParser_->Finish();
    networkParser_->Finish();
    processParser_->Finish();
    diskIOParser_->Finish();
    hisyseventParser_->Finish();
    // keep final upate perf and ebpf data time range
    ebpfDataParser_->Finish();
#if WITH_PERF
    perfDataParser_->Finish();
#endif

    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_TRACE,
                                                                      dataSourceTypeTraceClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_MEM, dataSourceTypeMemClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_HILOG,
                                                                      dataSourceTypeHilogClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_ALLOCATION,
                                                                      dataSourceTypeAllocationClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_FPS, dataSourceTypeFpsClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_NETWORK,
                                                                      dataSourceTypeNetworkClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_DISKIO,
                                                                      dataSourceTypeDiskioClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_CPU, dataSourceTypeCpuClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_PROCESS,
                                                                      dataSourceTypeProcessClockid_);
    traceDataCache_->GetDataSourceClockIdData()->SetDataSourceClockId(DATA_SOURCE_TYPE_HISYSEVENT,
                                                                      dataSourceTypeHisyseventClockid_);
    traceDataCache_->GetDataSourceClockIdData()->Finish();
    dataSegArray_.reset();
}

void HtraceParser::ParseTraceDataItem(const std::string& buffer)
{
    int head = rawDataHead_;
    if (!supportThread_) {
        dataSegArray_[head].seg = std::move(buffer);
        dataSegArray_[head].status = TS_PARSE_STATUS_SEPRATED;
        ParserData(dataSegArray_[head]);
        return;
    }
    while (!toExit_) {
        if (dataSegArray_[head].status.load() != TS_PARSE_STATUS_INIT) {
            usleep(sleepDur_);
            continue;
        }
        dataSegArray_[head].seg = std::move(buffer);
        dataSegArray_[head].status = TS_PARSE_STATUS_SEPRATED;
        rawDataHead_ = (rawDataHead_ + 1) % MAX_SEG_ARRAY_SIZE;
        break;
    }
    if (!parseThreadStarted_) {
        parseThreadStarted_ = true;
        int tmp = maxThread_;
        while (tmp--) {
            parserThreadCount_++;
            std::thread ParseTypeThread(&HtraceParser::ParseThread, this);
            ParseTypeThread.detach();
            TS_LOGD("parser Thread:%d/%d start working ...\n", maxThread_ - tmp, maxThread_);
        }
    }
}
void HtraceParser::FilterData(HtraceDataSegment& seg)
{
    if (seg.dataType == DATA_SOURCE_TYPE_TRACE) {
        if (seg.traceData->ftrace_cpu_detail_size()) {
            htraceCpuDetailParser_->Parse(seg.traceData.get(), clock_); // has Event
        }
        if (seg.traceData->symbols_detail_size()) {
            htraceSymbolsDetailParser_->Parse(seg.traceData.get()); // has Event
        }
        if (seg.traceData->clocks_detail_size()) {
            htraceClockDetailParser_->Parse(seg.traceData.get()); // has Event
        }
    } else if (seg.dataType == DATA_SOURCE_TYPE_MEM) {
        htraceMemParser_->Parse(seg.memData, seg.timeStamp, seg.clockId);
    } else if (seg.dataType == DATA_SOURCE_TYPE_HILOG) {
        htraceHiLogParser_->Parse(seg.logData);
    } else if (seg.dataType == DATA_SOURCE_TYPE_ALLOCATION) {
        htraceNativeHookParser_->SortNativeHookData(seg.batchNativeHookData);
    } else if (seg.dataType == DATA_SOURCE_TYPE_FPS) {
        htraceHidumpParser_->Parse(seg.hidumpInfo);
        dataSourceTypeFpsClockid_ = htraceHidumpParser_->ClockId();
    } else if (seg.dataType == DATA_SOURCE_TYPE_NETWORK) {
        networkParser_->Parse(seg.networkInfo, seg.timeStamp);
    } else if (seg.dataType == DATA_SOURCE_TYPE_CPU) {
        cpuUsageParser_->Parse(seg.cpuInfo, seg.timeStamp);
    } else if (seg.dataType == DATA_SOURCE_TYPE_PROCESS) {
        processParser_->Parse(seg.processInfo, seg.timeStamp);
    } else if (seg.dataType == DATA_SOURCE_TYPE_DISKIO) {
        diskIOParser_->Parse(seg.diskIOInfo, seg.timeStamp);
    } else if (seg.dataType == DATA_SOURCE_TYPE_HISYSEVENT) {
        hisyseventParser_->Parse(seg.hisyseventInfo, seg.timeStamp);
    }
    if (supportThread_) {
        filterHead_ = (filterHead_ + 1) % MAX_SEG_ARRAY_SIZE;
    }
    seg.status = TS_PARSE_STATUS_INIT;
}
void HtraceParser::FilterThread()
{
    TS_LOGI("filter thread start work!");
    while (1) {
        HtraceDataSegment& seg = dataSegArray_[filterHead_];
        if (seg.status.load() == TS_PARSE_STATUS_INVALID) {
            seg.status = TS_PARSE_STATUS_INIT;
            filterHead_ = (filterHead_ + 1) % MAX_SEG_ARRAY_SIZE;
            streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_OTHER, STAT_EVENT_DATA_INVALID);
            TS_LOGD("seprateHead_d:\t%d, parseHead_:\t%d, filterHead_:\t%d\n", rawDataHead_, parseHead_, filterHead_);
            continue;
        }
        if (seg.status.load() != TS_PARSE_STATUS_PARSED) {
            if (toExit_ && !parserThreadCount_) {
                TS_LOGI("exiting Filter Thread");
                exited_ = true;
                filterThreadStarted_ = false;
                TS_LOGI("seprateHead:\t%d, parseHead_:\t%d, filterHead_:\t%d, status:%d\n", rawDataHead_, parseHead_,
                        filterHead_, seg.status.load());
                return;
            }
            TS_LOGD("seprateHead:\t%d, parseHead_:\t%d, filterHead_:\t%d, status:%d\n", rawDataHead_, parseHead_,
                    filterHead_, seg.status.load());
            usleep(sleepDur_);
            continue;
        }
        FilterData(seg);
    }
}

void HtraceParser::ParserData(HtraceDataSegment& dataSeg)
{
    ProfilerPluginData pluginData;
    if (!pluginData.ParseFromArray(dataSeg.seg.data(), static_cast<int>(dataSeg.seg.length()))) {
        TS_LOGW("ProfilerPluginData ParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    dataSeg.timeStamp = pluginData.tv_nsec() + pluginData.tv_sec() * SEC_TO_NS;
    if (pluginData.name() == "memory-plugin") {
        ParseMemory(pluginData, dataSeg);
    } else if (pluginData.name() == "hilog-plugin" || pluginData.name() == "/data/local/tmp/libhilogplugin.z.so") {
        ParseHilog(pluginData, dataSeg);
    } else if (pluginData.name() == "ftrace-plugin" || pluginData.name() == "/data/local/tmp/libftrace_plugin.z.so") {
        ParseFtrace(pluginData, dataSeg);
    } else if (pluginData.name() == "nativehook" || pluginData.name() == "hookdaemon") {
        ParseNativeHook(pluginData, dataSeg);
    } else if (pluginData.name() == "hidump-plugin" || pluginData.name() == "/data/local/tmp/libhidumpplugin.z.so") {
        ParseFPS(pluginData, dataSeg);
    } else if (pluginData.name() == "cpu-plugin") {
        ParseCpuUsage(pluginData, dataSeg);
    } else if (pluginData.name() == "network-plugin") {
        ParseNetwork(pluginData, dataSeg);
    } else if (pluginData.name() == "diskio-plugin") {
        ParseDiskIO(pluginData, dataSeg);
    } else if (pluginData.name() == "process-plugin") {
        ParseProcess(pluginData, dataSeg);
    } else if (pluginData.name() == "hisysevent-plugin") {
        ParseHisysevent(pluginData, dataSeg);
    } else {
#if IS_WASM
        TraceStreamer_Plugin_Out_Filter(pluginData.data().data(), pluginData.data().length(), pluginData.name());
#endif
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_OTHER, STAT_EVENT_DATA_INVALID);
        return;
    }
    if (!supportThread_) { // do it only in wasm mode, wasm noThead_ will be true
        FilterData(dataSeg);
    }
}
void HtraceParser::ParseThread()
{
    TS_LOGI("parser thread start work!\n");
    while (1) {
        if (supportThread_ && !filterThreadStarted_) {
            filterThreadStarted_ = true;
            std::thread ParserThread(&HtraceParser::FilterThread, this);
            TS_LOGD("FilterThread start working ...\n");
            ParserThread.detach();
        }
        int head = GetNextSegment();
        if (head < 0) {
            if (head == ERROR_CODE_EXIT) {
                TS_LOGI("parse thread exit\n");
                return;
            } else if (head == ERROR_CODE_NODATA) {
                continue;
            }
        }
        HtraceDataSegment& dataSeg = dataSegArray_[head];
        ParserData(dataSeg);
    }
}

void HtraceParser::ParseMemory(const ProfilerPluginData& pluginData, HtraceDataSegment& dataSeg)
{
    dataSeg.dataType = DATA_SOURCE_TYPE_MEM;
    BuiltinClocks clockId = TS_CLOCK_REALTIME;
    auto clockIdTemp = pluginData.clock_id();
    if (clockIdTemp == ProfilerPluginData_ClockId_CLOCKID_REALTIME) {
        clockId = TS_CLOCK_REALTIME;
    }
    dataSourceTypeMemClockid_ = clockId;
    dataSeg.memData.Clear();
    if (!dataSeg.memData.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    if (dataSeg.memData.processesinfo_size()) {
        dataSeg.dataType = DATA_SOURCE_TYPE_MEM;
        dataSeg.clockId = clockId;
        dataSeg.status = TS_PARSE_STATUS_PARSED;
    } else if (dataSeg.memData.meminfo_size()) {
        dataSeg.dataType = DATA_SOURCE_TYPE_MEM;
        dataSeg.clockId = clockId;
        dataSeg.status = TS_PARSE_STATUS_PARSED;
    } else if (dataSeg.memData.vmeminfo_size()) {
        dataSeg.dataType = DATA_SOURCE_TYPE_MEM;
        dataSeg.clockId = clockId;
        dataSeg.status = TS_PARSE_STATUS_PARSED;
    } else {
        dataSeg.status = TS_PARSE_STATUS_INVALID;
    }
}
void HtraceParser::ParseHilog(const ProfilerPluginData& pluginData, HtraceDataSegment& dataSeg)
{
    dataSeg.dataType = DATA_SOURCE_TYPE_HILOG;
    dataSourceTypeHilogClockid_ = TS_CLOCK_REALTIME;
    if (!dataSeg.logData.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    if (dataSeg.logData.info_size()) {
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_INVALID;
}
void HtraceParser::ParseFtrace(const ProfilerPluginData& pluginData, HtraceDataSegment& dataSeg)
{
    dataSeg.dataType = DATA_SOURCE_TYPE_TRACE;
    dataSeg.traceData = std::make_unique<TracePluginResult>();
    if (!dataSeg.traceData->ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    if (dataSeg.traceData->ftrace_cpu_stats_size()) {
        auto cpuStats = dataSeg.traceData->ftrace_cpu_stats(0);
        auto s = cpuStats.per_cpu_stats(0);
        TS_LOGD("s.overrun():%lu", s.overrun());
        TS_LOGD("s.dropped_events():%lu", s.dropped_events());
        auto clock = cpuStats.trace_clock();
        if (clock == "boot") {
            clock_ = TS_CLOCK_BOOTTIME;
        }
        dataSeg.clockId = clock_;
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    dataSourceTypeTraceClockid_ = TS_CLOCK_BOOTTIME;
    if (dataSeg.traceData->clocks_detail_size() || dataSeg.traceData->ftrace_cpu_detail_size() ||
        dataSeg.traceData->symbols_detail_size()) {
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_INVALID;
}

void HtraceParser::ParseNativeHook(const ProfilerPluginData& pluginData, HtraceDataSegment& dataSeg)
{
    dataSourceTypeAllocationClockid_ = TS_CLOCK_REALTIME;
    dataSeg.dataType = DATA_SOURCE_TYPE_ALLOCATION;
    if (!dataSeg.batchNativeHookData.ParseFromArray(pluginData.data().data(),
                                                    static_cast<int>(pluginData.data().size()))) {
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    if (dataSeg.batchNativeHookData.events_size()) {
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_INVALID;
}

void HtraceParser::ParseFPS(const ProfilerPluginData& pluginData, HtraceDataSegment& dataSeg)
{
    dataSeg.dataType = DATA_SOURCE_TYPE_FPS;
    if (!dataSeg.hidumpInfo.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    if (dataSeg.hidumpInfo.fps_event_size()) {
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_INVALID;
}

void HtraceParser::ParseCpuUsage(const ProfilerPluginData& pluginData, HtraceDataSegment &dataSeg)
{
    dataSourceTypeProcessClockid_ = TS_CLOCK_REALTIME;
    dataSeg.dataType = DATA_SOURCE_TYPE_CPU;
    if (!dataSeg.cpuInfo.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_CPU_USAGE, STAT_EVENT_DATA_INVALID);
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    if (dataSeg.cpuInfo.has_cpu_usage_info() || dataSeg.cpuInfo.thread_info_size()) {
        dataSeg.status = TS_PARSE_STATUS_PARSED;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_INVALID;
}
void HtraceParser::ParseNetwork(const ProfilerPluginData& pluginData, HtraceDataSegment &dataSeg)
{
    dataSourceTypeProcessClockid_ = TS_CLOCK_REALTIME;
    dataSeg.dataType = DATA_SOURCE_TYPE_NETWORK;
    if (!dataSeg.networkInfo.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_NETWORK, STAT_EVENT_DATA_INVALID);
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_PARSED;
}
void HtraceParser::ParseDiskIO(const ProfilerPluginData& pluginData, HtraceDataSegment &dataSeg)
{
    dataSourceTypeProcessClockid_ = TS_CLOCK_REALTIME;
    dataSeg.dataType = DATA_SOURCE_TYPE_DISKIO;
    if (!dataSeg.diskIOInfo.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_DISKIO, STAT_EVENT_DATA_INVALID);
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_PARSED;
}

void HtraceParser::ParseProcess(const ProfilerPluginData& pluginData, HtraceDataSegment &dataSeg)
{
    dataSourceTypeProcessClockid_ = TS_CLOCK_BOOTTIME;
    dataSeg.dataType = DATA_SOURCE_TYPE_PROCESS;
    if (!dataSeg.processInfo.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_PROCESS, STAT_EVENT_DATA_INVALID);
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    dataSeg.timeStamp = pluginData.tv_nsec() + pluginData.tv_sec() * SEC_TO_NS;
    dataSeg.status = TS_PARSE_STATUS_PARSED;
}

void HtraceParser::ParseHisysevent(const ProfilerPluginData& pluginData, HtraceDataSegment &dataSeg)
{
    dataSourceTypeHisyseventClockid_ = TS_CLOCK_REALTIME;
    dataSeg.dataType = DATA_SOURCE_TYPE_HISYSEVENT;
    if (!dataSeg.hisyseventInfo.ParseFromArray(pluginData.data().data(), static_cast<int>(pluginData.data().size()))) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_HISYSEVENT, STAT_EVENT_DATA_INVALID);
        TS_LOGW("tracePacketParseFromArray failed\n");
        dataSeg.status = TS_PARSE_STATUS_INVALID;
        return;
    }
    dataSeg.status = TS_PARSE_STATUS_PARSED;
}

int HtraceParser::GetNextSegment()
{
    int head;
    dataSegMux_.lock();
    head = parseHead_;
    HtraceDataSegment& seg = dataSegArray_[head];
    if (seg.status.load() != TS_PARSE_STATUS_SEPRATED) {
        if (toExit_) {
            parserThreadCount_--;
            TS_LOGI("exiting parser, parserThread Count:%d\n", parserThreadCount_);
            TS_LOGD("seprateHead_x:\t%d, parseHead_:\t%d, filterHead_:\t%d status:%d\n", rawDataHead_, parseHead_,
                    filterHead_, seg.status.load());
            dataSegMux_.unlock();
            if (!parserThreadCount_ && !filterThreadStarted_) {
                exited_ = true;
            }
            return ERROR_CODE_EXIT;
        }
        if (seg.status.load() == TS_PARSE_STATUS_PARSING) {
            dataSegMux_.unlock();
            usleep(sleepDur_);
            return ERROR_CODE_NODATA;
        }
        dataSegMux_.unlock();
        usleep(sleepDur_);
        return ERROR_CODE_NODATA;
    }
    parseHead_ = (parseHead_ + 1) % MAX_SEG_ARRAY_SIZE;
    seg.status = TS_PARSE_STATUS_PARSING;
    dataSegMux_.unlock();
    return head;
}
bool HtraceParser::ParseDataRecursively(std::deque<uint8_t>::iterator& packagesBegin, size_t& currentLength)
{
    if (!hasGotHeader_) {
        if (InitProfilerTraceFileHeader()) {
            packagesBuffer_.erase(packagesBuffer_.begin(), packagesBuffer_.begin() + PACKET_HEADER_LENGTH);
            currentLength -= PACKET_HEADER_LENGTH;
            packagesBegin += PACKET_HEADER_LENGTH;
            htraceCurentLength_ = profilerTraceFileHeader_.data.length;
            htraceCurentLength_ -= PACKET_HEADER_LENGTH;
            hasGotHeader_ = true;
            if (!currentLength) {
                return false;
            }
        } else {
            TS_LOGE("get profiler trace file header failed");
            return false;
        }
    }
    if (profilerTraceFileHeader_.data.dataType == ProfilerTraceFileHeader::HIPERF_DATA) {
        if (packagesBuffer_.size() >= profilerTraceFileHeader_.data.length - PACKET_HEADER_LENGTH) {
#if WITH_PERF
            auto size = profilerTraceFileHeader_.data.length - PACKET_HEADER_LENGTH;
            perfDataParser_->InitPerfDataAndLoad(packagesBuffer_, size);
            currentLength -= size;
            packagesBegin += size;
            profilerTraceFileHeader_.data.dataType = ProfilerTraceFileHeader::UNKNOW_TYPE;
            hasGotHeader_ = false;
            return true;
#endif
        }
        return false;
    }
    if (profilerTraceFileHeader_.data.dataType == ProfilerTraceFileHeader::STANDALONE_DATA) {
        if (EBPF_PLUGIN_NAME.compare(profilerTraceFileHeader_.data.standalonePluginName) == 0 &&
            packagesBuffer_.size() >= profilerTraceFileHeader_.data.length - PACKET_HEADER_LENGTH) {
            auto size = profilerTraceFileHeader_.data.length - PACKET_HEADER_LENGTH;
            ebpfDataParser_->InitAndParseEbpfData(packagesBuffer_, size);
            currentLength -= size;
            packagesBegin += size;
            profilerTraceFileHeader_.data.dataType = ProfilerTraceFileHeader::UNKNOW_TYPE;
            hasGotHeader_ = false;
            return true;
        }
#if IS_WASM
        if (packagesBuffer_.size() >= profilerTraceFileHeader_.data.length - PACKET_HEADER_LENGTH) {
            auto thirdPartySize = profilerTraceFileHeader_.data.length - PACKET_HEADER_LENGTH;
            auto buffer = std::make_unique<uint8_t[]>(thirdPartySize).get();
            std::copy(packagesBuffer_.begin(), packagesBuffer_.begin() + thirdPartySize, buffer);
            TraceStreamer_Plugin_Out_Filter(reinterpret_cast<const char*>(buffer), thirdPartySize,
                                            profilerTraceFileHeader_.data.standalonePluginName);
            return true;
        }
#endif
        return false;
    }
    while (1) {
        if (!hasGotSegLength_) {
            if (currentLength < PACKET_SEG_LENGTH) {
                break;
            }
            std::string bufferLine(packagesBegin, packagesBegin + PACKET_SEG_LENGTH);
            const uint32_t* len = reinterpret_cast<const uint32_t*>(bufferLine.data());
            nextLength_ = *len;
            htraceLength_ += nextLength_ + PACKET_SEG_LENGTH;
            hasGotSegLength_ = true;
            currentLength -= PACKET_SEG_LENGTH;
            packagesBegin += PACKET_SEG_LENGTH;
            htraceCurentLength_ -= PACKET_SEG_LENGTH;
        }
        if (currentLength < nextLength_) {
            break;
        }
        std::string bufferLine(packagesBegin, packagesBegin + nextLength_);
        ParseTraceDataItem(bufferLine);
        hasGotSegLength_ = false;
        packagesBegin += nextLength_;
        currentLength -= nextLength_;
        if (nextLength_ > htraceCurentLength_) {
            TS_LOGE("fatal error, data length not match nextLength_:%u, htraceCurentLength_:%llu", nextLength_,
                    htraceCurentLength_);
        }
        htraceCurentLength_ -= nextLength_;
        if (htraceCurentLength_ == 0) {
            hasGotHeader_ = false;
            packagesBuffer_.erase(packagesBuffer_.begin(), packagesBegin);
            profilerTraceFileHeader_.data.dataType = ProfilerTraceFileHeader::UNKNOW_TYPE;
            TS_LOGW("read proto finished!");
            return ParseDataRecursively(packagesBegin, currentLength);
        }
    }
    return true;
}
void HtraceParser::ParseTraceDataSegment(std::unique_ptr<uint8_t[]> bufferStr, size_t size)
{
    packagesBuffer_.insert(packagesBuffer_.end(), &bufferStr[0], &bufferStr[size]);
    auto packagesBegin = packagesBuffer_.begin();
    auto currentLength = packagesBuffer_.size();
    if (ParseDataRecursively(packagesBegin, currentLength)) {
        packagesBuffer_.erase(packagesBuffer_.begin(), packagesBegin);
    }
    return;
}

bool HtraceParser::InitProfilerTraceFileHeader()
{
    if (packagesBuffer_.size() < PACKET_HEADER_LENGTH) {
        TS_LOGE("buffer size less than profiler trace file header");
        return false;
    }
    uint8_t buffer[PACKET_HEADER_LENGTH];
    memset_s(buffer, PACKET_HEADER_LENGTH, 0, PACKET_HEADER_LENGTH);
    int i = 0;
    for (auto it = packagesBuffer_.begin(); it != packagesBuffer_.begin() + PACKET_HEADER_LENGTH; ++it, ++i) {
        buffer[i] = *it;
    }
    auto ret = memcpy_s(&profilerTraceFileHeader_, sizeof(profilerTraceFileHeader_), buffer, PACKET_HEADER_LENGTH);
    if (ret == -1 || profilerTraceFileHeader_.data.magic != ProfilerTraceFileHeader::HEADER_MAGIC) {
        TS_LOGE("Get profiler trace file header failed! ret = %d, magic = %lx", ret,
                profilerTraceFileHeader_.data.magic);
        return false;
    }
    if (profilerTraceFileHeader_.data.length <= PACKET_HEADER_LENGTH) {
        TS_LOGE("Profiler Trace data is truncated!!!");
        return false;
    }
    TS_LOGI("magic = %llx, length = %llx, dataType = %llx, boottime = %llx", profilerTraceFileHeader_.data.magic,
            profilerTraceFileHeader_.data.length, profilerTraceFileHeader_.data.dataType,
            profilerTraceFileHeader_.data.boottime);
#if IS_WASM
    const int DATA_TYPE_CLOCK = 100;
    int componentId = DATA_TYPE_CLOCK;
    TraceStreamer_Plugin_Out_SendData(reinterpret_cast<char*>(&profilerTraceFileHeader_),
                                      sizeof(profilerTraceFileHeader_), DATA_TYPE_CLOCK);
#endif
    htraceClockDetailParser_->Parse(&profilerTraceFileHeader_);
    return true;
}
} // namespace TraceStreamer
} // namespace SysTuning
