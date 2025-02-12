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
#include "htrace_event_parser.h"
#include <string>
#include "binder_filter.h"
#include "binder.pb.h"
#include "clock_filter.h"
#include "cpu_filter.h"
#include "irq_filter.h"
#include "irq.pb.h"
#include "log.h"
#include "measure_filter.h"
#include "process_filter.h"
#include "slice_filter.h"
#include "stat_filter.h"
#include "symbols_filter.h"
#include "system_event_measure_filter.h"
#include "thread_state.h"
namespace SysTuning {
namespace TraceStreamer {
HtraceEventParser::HtraceEventParser(TraceDataCache* dataCache, const TraceStreamerFilters* filter)
    : EventParserBase(dataCache, filter),
      workQueueId_(dataCache->dataDict_.GetStringIndex("workqueue")),
      printEventParser_(traceDataCache_, streamFilters_)
{
    eventToFunctionMap_ = {{config_.eventNameMap_.at(TRACE_EVENT_BINDER_TRANSACTION),
                            std::bind(&HtraceEventParser::BinderTractionEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_BINDER_TRANSACTION_RECEIVED),
                            std::bind(&HtraceEventParser::BinderTractionReceivedEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_BINDER_TRANSACTION_ALLOC_BUF),
                            std::bind(&HtraceEventParser::BinderTractionAllocBufEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_BINDER_TRANSACTION_LOCK),
                            std::bind(&HtraceEventParser::BinderTractionLockEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_BINDER_TRANSACTION_LOCKED),
                            std::bind(&HtraceEventParser::BinderTractionLockedEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_BINDER_TRANSACTION_UNLOCK),
                            std::bind(&HtraceEventParser::BinderTractionUnLockEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SCHED_SWITCH),
                            std::bind(&HtraceEventParser::SchedSwitchEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_TASK_RENAME),
                            std::bind(&HtraceEventParser::TaskRenameEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_TASK_NEWTASK),
                            std::bind(&HtraceEventParser::TaskNewtaskEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_PRINT),
                            std::bind(&HtraceEventParser::ParsePrintEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SCHED_WAKEUP),
                            std::bind(&HtraceEventParser::SchedWakeupEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SCHED_WAKEUP_NEW),
                            std::bind(&HtraceEventParser::SchedWakeupNewEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_PROCESS_EXIT),
                            std::bind(&HtraceEventParser::ProcessExitEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_PROCESS_FREE),
                            std::bind(&HtraceEventParser::ProcessFreeEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SCHED_WAKING),
                            std::bind(&HtraceEventParser::SchedWakingEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CPU_IDLE),
                            std::bind(&HtraceEventParser::CpuIdleEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CPU_FREQUENCY),
                            std::bind(&HtraceEventParser::CpuFrequencyEvent, this, std::placeholders::_1)},
                            {config_.eventNameMap_.at(TRACE_EVENT_CPU_FREQUENCY_LIMITS),
                            std::bind(&HtraceEventParser::CpuFrequencyLimitsEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SUSPEND_RESUME),
                            std::bind(&HtraceEventParser::SuspendResumeEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_WORKQUEUE_EXECUTE_START),
                            std::bind(&HtraceEventParser::WorkqueueExecuteStartEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_WORKQUEUE_EXECUTE_END),
                            std::bind(&HtraceEventParser::WorkqueueExecuteEndEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CLOCK_SET_RATE),
                            std::bind(&HtraceEventParser::ClockSetRateEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CLOCK_ENABLE),
                            std::bind(&HtraceEventParser::ClockEnableEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CLOCK_DISABLE),
                            std::bind(&HtraceEventParser::ClockDisableEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CLK_SET_RATE),
                            std::bind(&HtraceEventParser::ClkSetRateEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CLK_ENABLE),
                            std::bind(&HtraceEventParser::ClkEnableEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_CLK_DISABLE),
                            std::bind(&HtraceEventParser::ClkDisableEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_IRQ_HANDLER_ENTRY),
                            std::bind(&HtraceEventParser::IrqHandlerEntryEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_IRQ_HANDLER_EXIT),
                            std::bind(&HtraceEventParser::IrqHandlerExitEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SOFTIRQ_ENTRY),
                            std::bind(&HtraceEventParser::SoftIrqEntryEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SOFTIRQ_RAISE),
                            std::bind(&HtraceEventParser::SoftIrqRaiseEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SOFTIRQ_EXIT),
                            std::bind(&HtraceEventParser::SoftIrqExitEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SYS_ENTRY),
                            std::bind(&HtraceEventParser::SysEnterEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_SYS_EXIT),
                            std::bind(&HtraceEventParser::SysExitEvent, this, std::placeholders::_1)},
                           {config_.eventNameMap_.at(TRACE_EVENT_OOM_SCORE_ADJ_UPDATE),
                            std::bind(&HtraceEventParser::OomScoreAdjUpdate, this, std::placeholders::_1)}};
}

HtraceEventParser::~HtraceEventParser()
{
    TS_LOGI("thread count:%u", static_cast<unsigned int>(tids_.size()));
    TS_LOGI("process count:%u", static_cast<unsigned int>(pids_.size()));
    TS_LOGI("ftrace ts MIN:%llu, MAX:%llu", static_cast<unsigned long long>(ftraceStartTime_),
            static_cast<unsigned long long>(ftraceEndTime_));
}
void HtraceEventParser::ParseDataItem(const FtraceCpuDetailMsg* cpuDetail, BuiltinClocks clock)
{
    eventCpu_ = cpuDetail->cpu();
    auto events = cpuDetail->event();
    if (!events.size()) {
        return;
    }
    if (cpuDetail->overwrite()) {
        if (!lastOverwrite_) {
            lastOverwrite_ = cpuDetail->overwrite();
        }
        if (lastOverwrite_ != cpuDetail->overwrite()) {
            TS_LOGW("lost events:%lu", cpuDetail->overwrite() - lastOverwrite_);
            lastOverwrite_ = cpuDetail->overwrite();
        }
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_OTHER, STAT_EVENT_DATA_LOST);
    }
    // parser cpu event
    for (auto i = 0; i < events.size(); i++) {
        auto event = cpuDetail->event(i);
        eventTimestamp_ = event.timestamp();
        comm_ = event.comm();
        ftraceStartTime_ = std::min(ftraceStartTime_, eventTimestamp_);
        ftraceEndTime_ = std::max(ftraceEndTime_, eventTimestamp_);
        eventTimestamp_ = streamFilters_->clockFilter_->ToPrimaryTraceTime(clock, eventTimestamp_);
        traceDataCache_->UpdateTraceTime(eventTimestamp_);
        if (event.tgid() != INVALID_INT32) {
            eventPid_ = event.tgid();
            if (!pids_.count(eventPid_)) {
                pids_.insert(eventPid_);
            }
            streamFilters_->processFilter_->GetOrCreateThreadWithPid(eventPid_, eventPid_);
        }
        if (event.common_fields().pid() != INVALID_INT32) {
            eventTid_ = event.common_fields().pid();
            if (!tids_.count(eventTid_)) {
                tids_.insert(eventTid_);
            }
            streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventTid_);
        }
        if (eventTid_ != INVALID_INT32 && eventPid_ != INVALID_INT32) {
            streamFilters_->processFilter_->GetOrCreateThreadWithPid(eventTid_, eventPid_);
        }
        // remember all event
        eventList_.push_back(std::move(
            std::make_unique<EventInfo>(comm_, eventTimestamp_, eventCpu_, eventPid_, eventTid_, std::move(event))));
        // push all events in queue and finally release it, the data may not be released
        // this may limit the max size of data, so we parser data periodicity
        FilterAllEventsTemp();
    }
}
void HtraceEventParser::DealEvent(const FtraceEvent& event)
{
    streamFilters_->processFilter_->UpdateOrCreateThreadWithPidAndName(event.common_fields().pid(), event.tgid(),
                                                                       event.comm());
    if (event.has_sched_switch_format()) {
        InvokeFunc(TRACE_EVENT_SCHED_SWITCH, event.sched_switch_format());
    } else if (event.has_task_rename_format()) {
        InvokeFunc(TRACE_EVENT_TASK_RENAME, event.task_rename_format());
    } else if (event.has_task_newtask_format()) {
        InvokeFunc(TRACE_EVENT_TASK_NEWTASK, event.task_newtask_format());
    } else if (event.has_sched_wakeup_format()) {
        InvokeFunc(TRACE_EVENT_SCHED_WAKEUP, event.sched_wakeup_format());
    } else if (event.has_sched_wakeup_new_format()) {
        InvokeFunc(TRACE_EVENT_SCHED_WAKEUP, event.sched_wakeup_new_format());
    } else if (event.has_sched_process_exit_format()) {
        InvokeFunc(TRACE_EVENT_PROCESS_EXIT, event.sched_process_exit_format());
    } else if (event.has_sched_process_free_format()) {
        InvokeFunc(TRACE_EVENT_PROCESS_FREE, event.sched_process_free_format());
    } else if (event.has_sched_waking_format()) {
        InvokeFunc(TRACE_EVENT_SCHED_WAKING, event.sched_waking_format());
    } else if (event.has_cpu_idle_format()) {
        InvokeFunc(TRACE_EVENT_CPU_IDLE, event.cpu_idle_format());
    } else if (event.has_cpu_frequency_format()) {
        InvokeFunc(TRACE_EVENT_CPU_FREQUENCY, event.cpu_frequency_format());
    } else if (event.has_cpu_frequency_limits_format()) {
        InvokeFunc(TRACE_EVENT_CPU_FREQUENCY_LIMITS, event.cpu_frequency_limits_format());
    } else if (event.has_print_format()) {
        InvokeFunc(TRACE_EVENT_PRINT, event.print_format());
    } else if (event.has_suspend_resume_format()) {
        InvokeFunc(TRACE_EVENT_SUSPEND_RESUME, event.suspend_resume_format());
    } else if (event.has_workqueue_execute_start_format()) {
        InvokeFunc(TRACE_EVENT_WORKQUEUE_EXECUTE_START, event.workqueue_execute_start_format());
    } else if (event.has_workqueue_execute_end_format()) {
        InvokeFunc(TRACE_EVENT_WORKQUEUE_EXECUTE_END, event.workqueue_execute_end_format());
    } else if (event.has_clock_disable_format()) {
        InvokeFunc(TRACE_EVENT_CLOCK_DISABLE, event.clock_disable_format());
    } else if (event.has_clock_enable_format()) {
        InvokeFunc(TRACE_EVENT_CLOCK_ENABLE, event.clock_enable_format());
    } else if (event.has_clock_set_rate_format()) {
        InvokeFunc(TRACE_EVENT_CLOCK_SET_RATE, event.clock_set_rate_format());
    } else if (event.has_clk_disable_format()) {
        InvokeFunc(TRACE_EVENT_CLK_DISABLE, event.clk_disable_format());
    } else if (event.has_clk_enable_format()) {
        InvokeFunc(TRACE_EVENT_CLK_ENABLE, event.clk_enable_format());
    } else if (event.has_clk_set_rate_format()) {
        InvokeFunc(TRACE_EVENT_CLK_SET_RATE, event.clk_set_rate_format());
    } else if (event.has_sys_enter_format()) {
        InvokeFunc(TRACE_EVENT_SYS_ENTRY, event.sys_enter_format());
    } else if (event.has_sys_exit_format()) {
        InvokeFunc(TRACE_EVENT_SYS_EXIT, event.sys_exit_format());
    } else if (event.has_binder_transaction_format()) {
        InvokeFunc(TRACE_EVENT_BINDER_TRANSACTION, event.binder_transaction_format());
    } else if (event.has_binder_transaction_received_format()) {
        InvokeFunc(TRACE_EVENT_BINDER_TRANSACTION_RECEIVED, event.binder_transaction_received_format());
    } else if (event.has_binder_transaction_alloc_buf_format()) {
        InvokeFunc(TRACE_EVENT_BINDER_TRANSACTION_ALLOC_BUF, event.binder_transaction_alloc_buf_format());
    } else if (event.has_binder_lock_format()) {
        InvokeFunc(TRACE_EVENT_BINDER_TRANSACTION_LOCK, event.binder_lock_format());
    } else if (event.has_binder_unlock_format()) {
        InvokeFunc(TRACE_EVENT_BINDER_TRANSACTION_UNLOCK, event.binder_unlock_format());
    } else if (event.has_binder_locked_format()) {
        InvokeFunc(TRACE_EVENT_BINDER_TRANSACTION_LOCKED, event.binder_locked_format());
    } else if (event.has_irq_handler_entry_format()) {
        InvokeFunc(TRACE_EVENT_IRQ_HANDLER_ENTRY, event.irq_handler_entry_format());
    } else if (event.has_irq_handler_exit_format()) {
        InvokeFunc(TRACE_EVENT_IRQ_HANDLER_EXIT, event.irq_handler_exit_format());
    } else if (event.has_softirq_entry_format()) {
        InvokeFunc(TRACE_EVENT_SOFTIRQ_ENTRY, event.softirq_entry_format());
    } else if (event.has_softirq_exit_format()) {
        InvokeFunc(TRACE_EVENT_SOFTIRQ_EXIT, event.softirq_exit_format());
    } else if (event.has_oom_score_adj_update_format()) {
        InvokeFunc(TRACE_EVENT_OOM_SCORE_ADJ_UPDATE, event.oom_score_adj_update_format());
    } else if (event.has_signal_generate_format()) {
        InvokeFunc(TRACE_EVENT_SIGNAL_GENERATE, event.signal_generate_format());
    } else if (event.has_signal_deliver_format()) {
        InvokeFunc(TRACE_EVENT_SIGNAL_DELIVER, event.signal_deliver_format());
    } else {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_OTHER, STAT_EVENT_NOTSUPPORTED);
        TS_LOGD("has_rpc_socket_shutdown_format\n");
    }
}
bool HtraceEventParser::BinderTractionAllocBufEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BINDER_TRANSACTION_ALLOC_BUF, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const BinderTransactionAllocBufFormat&>(event);
    uint64_t dataSize = msg.data_size();
    uint64_t offsetsSize = msg.offsets_size();
    streamFilters_->binderFilter_->TransactionAllocBuf(eventTimestamp_, eventTid_, dataSize, offsetsSize);
    TS_LOGD("dataSize:%lu, offsetSize:%lu", dataSize, offsetsSize);
    return true;
}
bool HtraceEventParser::BinderTractionEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BINDER_TRANSACTION, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const BinderTransactionFormat&>(event);
    int32_t destNode = msg.target_node();
    int32_t destTgid = msg.to_proc();
    int32_t destTid = msg.to_thread();
    int32_t transactionId = msg.debug_id();
    bool isReply = msg.reply() == 1;
    uint32_t flags = msg.flags();
    TS_LOGD("destNode:%d, destTgid:%d, destTid:%d, transactionId:%d, isReply:%d flags:%d, code:%d", destNode, destTgid,
            destTid, transactionId, isReply, flags, msg.code());
    streamFilters_->binderFilter_->SendTraction(eventTimestamp_, eventTid_, transactionId, destNode, destTgid, destTid,
                                                isReply, flags, msg.code());
    return true;
}
bool HtraceEventParser::BinderTractionReceivedEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BINDER_TRANSACTION_RECEIVED, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const BinderTransactionReceivedFormat&>(event);
    int32_t transactionId = msg.debug_id();
    streamFilters_->binderFilter_->ReceiveTraction(eventTimestamp_, eventTid_, transactionId);
    TS_LOGD("transactionId:%d", transactionId);
    return true;
}
bool HtraceEventParser::BinderTractionLockEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BINDER_TRANSACTION_LOCK, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const BinderLockFormat&>(event);
    std::string tag = msg.tag();
    streamFilters_->binderFilter_->TractionLock(eventTimestamp_, eventTid_, tag);
    TS_LOGD("tag:%s", tag.c_str());
    return true;
}
bool HtraceEventParser::BinderTractionLockedEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BINDER_TRANSACTION_LOCKED, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const BinderLockedFormat&>(event);
    std::string tag = msg.tag();
    streamFilters_->binderFilter_->TractionLocked(eventTimestamp_, eventTid_, tag);
    return true;
}
bool HtraceEventParser::BinderTractionUnLockEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BINDER_TRANSACTION_UNLOCK, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const BinderUnlockFormat&>(event);
    std::string tag = msg.tag();
    TS_LOGD("tag:%s", tag.c_str());
    streamFilters_->binderFilter_->TractionUnlock(eventTimestamp_, eventTid_, tag);
    return true;
}
bool HtraceEventParser::SchedSwitchEvent(const MessageLite& event)
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_SWITCH, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SchedSwitchFormat&>(event);
    uint32_t prevPrioValue = msg.prev_prio();
    uint32_t nextPrioValue = msg.next_prio();
    uint32_t prevPidValue = msg.prev_pid();
    uint32_t nextPidValue = msg.next_pid();
    if (!tids_.count(prevPidValue)) {
        tids_.insert(prevPidValue);
    }
    if (!tids_.count(nextPidValue)) {
        tids_.insert(nextPidValue);
    }
    std::string prevCommStr = msg.prev_comm();
    std::string nextCommStr = msg.next_comm();
    auto prevState = msg.prev_state();

    auto nextInternalTid =
        streamFilters_->processFilter_->UpdateOrCreateThreadWithName(eventTimestamp_, nextPidValue, nextCommStr);
    auto uprevtid =
        streamFilters_->processFilter_->UpdateOrCreateThreadWithName(eventTimestamp_, prevPidValue, prevCommStr);
    streamFilters_->cpuFilter_->InsertSwitchEvent(eventTimestamp_, eventCpu_, uprevtid,
                                                  static_cast<uint64_t>(prevPrioValue), prevState, nextInternalTid,
                                                  static_cast<uint64_t>(nextPrioValue));
    return true;
}
bool HtraceEventParser::ProcessExitEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_PROCESS_EXIT, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SchedProcessExitFormat&>(event);
    uint32_t pidValue = msg.pid();
    std::string commStr = msg.comm();
    auto iTid = streamFilters_->processFilter_->UpdateOrCreateThreadWithName(eventTimestamp_, pidValue, commStr);
    if (streamFilters_->cpuFilter_->InsertProcessExitEvent(eventTimestamp_, eventCpu_, iTid)) {
        return true;
    } else {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_PROCESS_EXIT, STAT_EVENT_NOTMATCH);
        return false;
    }
}
bool HtraceEventParser::ProcessFreeEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_PROCESS_FREE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SchedProcessFreeFormat&>(event);
    uint32_t pidValue = msg.pid();
    std::string commStr = msg.comm();
    auto iTid = streamFilters_->processFilter_->UpdateOrCreateThreadWithName(eventTimestamp_, pidValue, commStr);
    if (streamFilters_->cpuFilter_->InsertProcessFreeEvent(eventTimestamp_, iTid)) {
        return true;
    } else {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_PROCESS_FREE, STAT_EVENT_NOTMATCH);
        return false;
    }
}
bool HtraceEventParser::TaskRenameEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TASK_RENAME, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const TaskRenameFormat&>(event);
    auto prevCommStr = msg.newcomm();
    auto pidValue = msg.pid();
    return true;
}
bool HtraceEventParser::TaskNewtaskEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TASK_NEWTASK, STAT_EVENT_RECEIVED);
    // the clone flag from txt trace from kernel original is HEX, but when it is converted from proto
    // based trace, it will be OCT number, it is not stable, so we decide to ignore it
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TASK_NEWTASK, STAT_EVENT_NOTSUPPORTED);
    return true;
}
bool HtraceEventParser::ParsePrintEvent(const MessageLite& event)
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_PRINT, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const PrintFormat&>(event);
    printEventParser_.ParsePrintEvent(comm_, eventTimestamp_, eventTid_, msg.buf().c_str());
    if (!tids_.count(eventTid_)) {
        tids_.insert(eventTid_);
    }
    return true;
}
bool HtraceEventParser::SchedWakeupEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_WAKEUP, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SchedWakeupFormat&>(event);
    auto instants = traceDataCache_->GetInstantsData();

    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, msg.pid());
    InternalTid wakeupFromPid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventTid_);
    instants->AppendInstantEventData(eventTimestamp_, schedWakeupName_, internalTid, wakeupFromPid);
    std::optional<uint32_t> targetCpu = msg.target_cpu();
    if (targetCpu.has_value()) {
        traceDataCache_->GetRawData()->AppendRawData(0, eventTimestamp_, RAW_SCHED_WAKEUP, targetCpu.value(),
                                                     internalTid);
    } else {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_WAKEUP, STAT_EVENT_DATA_INVALID);
    }
    return true;
}
bool HtraceEventParser::SchedWakeupNewEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_WAKEUP_NEW, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SchedWakeupNewFormat&>(event);
    auto instants = traceDataCache_->GetInstantsData();

    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, msg.pid());
    InternalTid wakeupFromPid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventTid_);
    instants->AppendInstantEventData(eventTimestamp_, schedWakeupNewName_, internalTid, wakeupFromPid);
    std::optional<uint32_t> targetCpu = msg.target_cpu();
    if (targetCpu.has_value()) {
        traceDataCache_->GetRawData()->AppendRawData(0, eventTimestamp_, RAW_SCHED_WAKEUP, targetCpu.value(),
                                                     internalTid);
    } else {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_WAKEUP_NEW, STAT_EVENT_DATA_INVALID);
    }
    return true;
}
bool HtraceEventParser::SchedWakingEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_WAKING, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SchedWakingFormat&>(event);
    std::optional<uint32_t> wakePidValue = msg.pid();
    if (!wakePidValue.has_value()) {
        TS_LOGD("Failed to convert wake_pid");
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SCHED_WAKING, STAT_EVENT_DATA_INVALID);
        return false;
    }
    auto instants = traceDataCache_->GetInstantsData();
    InternalTid internalTid =
        streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, wakePidValue.value());
    InternalTid wakeupFromPid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventTid_);
    instants->AppendInstantEventData(eventTimestamp_, schedWakingName_, internalTid, wakeupFromPid);
    streamFilters_->cpuFilter_->InsertWakeupEvent(eventTimestamp_, internalTid);
    std::optional<uint32_t> targetCpu = msg.target_cpu();
    if (targetCpu.has_value()) {
        traceDataCache_->GetRawData()->AppendRawData(0, eventTimestamp_, RAW_SCHED_WAKING, targetCpu.value(),
                                                     wakeupFromPid);
    }
    return true;
}
bool HtraceEventParser::CpuIdleEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_IDLE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const CpuIdleFormat&>(event);
    std::optional<uint32_t> eventCpuValue = msg.cpu_id();
    std::optional<uint64_t> newStateValue = msg.state();
    if (!eventCpuValue.has_value()) {
        TS_LOGW("Failed to convert event cpu");
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_IDLE, STAT_EVENT_DATA_INVALID);
        return false;
    }
    if (!newStateValue.has_value()) {
        TS_LOGW("Failed to convert state");
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_IDLE, STAT_EVENT_DATA_INVALID);
        return false;
    }

    streamFilters_->cpuMeasureFilter_->AppendNewMeasureData(eventCpuValue.value(), cpuIdleName_, eventTimestamp_,
                                                            config_.GetStateValue(newStateValue.value()));

    // Add cpu_idle event to raw_data_table
    traceDataCache_->GetRawData()->AppendRawData(0, eventTimestamp_, RAW_CPU_IDLE, eventCpuValue.value(), 0);
    return true;
}
bool HtraceEventParser::CpuFrequencyEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_FREQUENCY, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const CpuFrequencyFormat&>(event);
    std::optional<uint64_t> newStateValue = msg.state();
    std::optional<uint32_t> eventCpuValue = msg.cpu_id();

    if (!newStateValue.has_value()) {
        TS_LOGW("Failed to convert state");
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_FREQUENCY, STAT_EVENT_DATA_INVALID);
        return false;
    }
    if (!eventCpuValue.has_value()) {
        TS_LOGW("Failed to convert event cpu");
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_FREQUENCY, STAT_EVENT_DATA_INVALID);
        return false;
    }

    streamFilters_->cpuMeasureFilter_->AppendNewMeasureData(eventCpuValue.value(), cpuFrequencyName_, eventTimestamp_,
                                                            newStateValue.value());
    return true;
}
bool HtraceEventParser::CpuFrequencyLimitsEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CPU_FREQUENCY_LIMITS, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const CpuFrequencyLimitsFormat&>(event);
    uint32_t maxFreq = msg.max_freq();
    uint32_t minFreq = msg.min_freq();
    uint32_t eventCpuValue = msg.cpu_id();
    streamFilters_->cpuMeasureFilter_->AppendNewMeasureData(eventCpuValue, cpuFrequencyLimitMaxNameId, eventTimestamp_,
                                                            maxFreq);
    streamFilters_->cpuMeasureFilter_->AppendNewMeasureData(eventCpuValue, cpuFrequencyLimitMinNameId, eventTimestamp_,
                                                            minFreq);
    return true;
}
bool HtraceEventParser::SuspendResumeEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SUSPEND_RESUME, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SuspendResumeFormat&>(event);
    int32_t val = msg.val();
    uint32_t start = msg.start();
    std::string action = msg.action();
    UNUSED(val);
    UNUSED(start);
    UNUSED(action);
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SUSPEND_RESUME, STAT_EVENT_NOTSUPPORTED);
    return true;
}
bool HtraceEventParser::WorkqueueExecuteStartEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_WORKQUEUE_EXECUTE_START, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const WorkqueueExecuteStartFormat&>(event);
    auto funcNameIndex = streamFilters_->symbolsFilter_->GetFunc(msg.function());
    size_t result = INVALID_UINT32;
    if (funcNameIndex == INVALID_UINT64) {
        std::string addrStr = "0x" + base::number(msg.function(), base::INTEGER_RADIX_TYPE_HEX);
        auto addStrIndex = traceDataCache_->GetDataIndex(addrStr);
        result = streamFilters_->sliceFilter_->BeginSlice(comm_, eventTimestamp_, eventPid_, eventPid_,
                                                          workQueueId_, addStrIndex);
    } else {
        result = streamFilters_->sliceFilter_->BeginSlice(comm_, eventTimestamp_, eventPid_, eventPid_,
                                                          workQueueId_, funcNameIndex);
    }

    traceDataCache_->GetInternalSlicesData()->AppendDistributeInfo();
    if (result == INVALID_UINT32) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_TRACING_MARK_WRITE, STAT_EVENT_DATA_LOST);
    }
    return true;
}
bool HtraceEventParser::WorkqueueExecuteEndEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_WORKQUEUE_EXECUTE_END, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const WorkqueueExecuteEndFormat&>(event);
    if (streamFilters_->sliceFilter_->EndSlice(eventTimestamp_, eventPid_, eventPid_, workQueueId_)) {
        streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_WORKQUEUE_EXECUTE_END, STAT_EVENT_NOTMATCH);
    }
    return true;
}
bool HtraceEventParser::ClockSetRateEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CLOCK_SET_RATE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const ClockSetRateFormat&>(event);
    DataIndex nameIndex = traceDataCache_->GetDataIndex(msg.name());
    streamFilters_->clockRateFilter_->AppendNewMeasureData(msg.cpu_id(), nameIndex, eventTimestamp_, msg.state());
    return true;
}
bool HtraceEventParser::ClockEnableEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CLOCK_ENABLE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const ClockEnableFormat&>(event);
    DataIndex nameIndex = traceDataCache_->GetDataIndex(msg.name());
    streamFilters_->clockEnableFilter_->AppendNewMeasureData(msg.cpu_id(), nameIndex, eventTimestamp_, msg.state());
    return true;
}
bool HtraceEventParser::ClockDisableEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CLOCK_DISABLE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const ClockDisableFormat&>(event);
    DataIndex nameIndex = traceDataCache_->GetDataIndex(msg.name());
    streamFilters_->clockDisableFilter_->AppendNewMeasureData(msg.cpu_id(), nameIndex, eventTimestamp_, msg.state());
    return true;
}
bool HtraceEventParser::ClkSetRateEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CLK_SET_RATE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const ClkSetRateFormat&>(event);
    DataIndex nameIndex = traceDataCache_->GetDataIndex(msg.name());
    streamFilters_->clkRateFilter_->AppendNewMeasureData(eventCpu_, nameIndex, eventTimestamp_, msg.rate());
    return true;
}
bool HtraceEventParser::ClkEnableEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CLK_ENABLE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const ClkEnableFormat&>(event);
    DataIndex nameIndex = traceDataCache_->GetDataIndex(msg.name());
    streamFilters_->clkEnableFilter_->AppendNewMeasureData(eventCpu_, nameIndex, eventTimestamp_, 1);
    return true;
}
bool HtraceEventParser::ClkDisableEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_CLK_DISABLE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const ClkDisableFormat&>(event);
    DataIndex nameIndex = traceDataCache_->GetDataIndex(msg.name());
    streamFilters_->clkDisableFilter_->AppendNewMeasureData(eventCpu_, nameIndex, eventTimestamp_, 0);
    return true;
}

bool HtraceEventParser::IrqHandlerEntryEvent(const MessageLite& event) const
{
    traceDataCache_->GetStatAndInfo()->IncreaseStat(TRACE_EVENT_IRQ_HANDLER_ENTRY, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const IrqHandlerEntryFormat&>(event);
    auto name = std::string_view(msg.name());
    streamFilters_->irqFilter_->IrqHandlerEntry(eventTimestamp_, eventCpu_, traceDataCache_->GetDataIndex(name));
    return true;
}
bool HtraceEventParser::IrqHandlerExitEvent(const MessageLite& event) const
{
    traceDataCache_->GetStatAndInfo()->IncreaseStat(TRACE_EVENT_IRQ_HANDLER_EXIT, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const IrqHandlerExitFormat&>(event);
    streamFilters_->irqFilter_->IrqHandlerExit(eventTimestamp_, eventCpu_, static_cast<uint32_t>(msg.ret()));
    return true;
}
bool HtraceEventParser::SoftIrqEntryEvent(const MessageLite& event) const
{
    traceDataCache_->GetStatAndInfo()->IncreaseStat(TRACE_EVENT_SOFTIRQ_ENTRY, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SoftirqEntryFormat&>(event);
    streamFilters_->irqFilter_->SoftIrqEntry(eventTimestamp_, eventCpu_, static_cast<uint32_t>(msg.vec()));
    return true;
}
bool HtraceEventParser::SoftIrqRaiseEvent(const MessageLite& event) const
{
    traceDataCache_->GetStatAndInfo()->IncreaseStat(TRACE_EVENT_SOFTIRQ_RAISE, STAT_EVENT_RECEIVED);
    traceDataCache_->GetStatAndInfo()->IncreaseStat(TRACE_EVENT_SOFTIRQ_RAISE, STAT_EVENT_NOTSUPPORTED);
    return true;
}
bool HtraceEventParser::SoftIrqExitEvent(const MessageLite& event) const
{
    traceDataCache_->GetStatAndInfo()->IncreaseStat(TRACE_EVENT_SOFTIRQ_EXIT, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SoftirqExitFormat&>(event);
    streamFilters_->irqFilter_->SoftIrqExit(eventTimestamp_, eventCpu_, static_cast<uint32_t>(msg.vec()));
    return true;
}
bool HtraceEventParser::SysEnterEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SYS_ENTRY, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SysEnterFormat&>(event);
    auto ipid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventPid_);
    traceDataCache_->GetSysCallData()->AppendSysCallData(msg.id(), sysEnterName_, ipid, eventTimestamp_, 0);
    return true;
}
bool HtraceEventParser::SysExitEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_SYS_EXIT, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SysExitFormat&>(event);
    auto ipid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventPid_);
    traceDataCache_->GetSysCallData()->AppendSysCallData(msg.id(), sysExitName_, ipid, eventTimestamp_, msg.ret());
    return true;
}

bool HtraceEventParser::OomScoreAdjUpdate(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_OOM_SCORE_ADJ_UPDATE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const OomScoreAdjUpdateFormat&>(event);
    streamFilters_->processMeasureFilter_->AppendNewMeasureData(msg.pid(), oomScoreAdjName_, eventTimestamp_,
                                                                msg.oom_score_adj());
    return true;
}

bool HtraceEventParser::SignalGenerateEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BLOCK_BIO_BACKMERGE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SignalGenerateFormat&>(event);
    InternalTid internalTid =
        streamFilters_->processFilter_->UpdateOrCreateThreadWithName(eventTimestamp_, msg.pid(), msg.comm());
    streamFilters_->threadFilter_->AppendNewMeasureData(internalTid, signalGenerateId_, eventTimestamp_, msg.sig());
    return true;
}
bool HtraceEventParser::SignalDeleverEvent(const MessageLite& event) const
{
    streamFilters_->statFilter_->IncreaseStat(TRACE_EVENT_BLOCK_BIO_BACKMERGE, STAT_EVENT_RECEIVED);
    const auto msg = static_cast<const SignalDeliverFormat&>(event);
    InternalTid internalTid = streamFilters_->processFilter_->UpdateOrCreateThread(eventTimestamp_, eventPid_);
    streamFilters_->threadFilter_->AppendNewMeasureData(internalTid, signalDeliverId_, eventTimestamp_, msg.sig());
    return true;
}
bool HtraceEventParser::InvokeFunc(const SupportedTraceEventType& eventType, const MessageLite& msgBase)
{
    auto eventName = config_.eventNameMap_.find(eventType);
    if (eventName == config_.eventNameMap_.end()) {
        // log warn
        streamFilters_->statFilter_->IncreaseStat(eventType, STAT_EVENT_NOTSUPPORTED);
        return false;
    }
    auto it = eventToFunctionMap_.find(eventName->second);
    if (it == eventToFunctionMap_.end()) {
        // log warn
        streamFilters_->statFilter_->IncreaseStat(eventType, STAT_EVENT_NOTSUPPORTED);
        return false;
    }
    it->second(msgBase);
    return true;
}
void HtraceEventParser::FilterAllEventsTemp()
{
    size_t maxBuffSize = 1000 * 1000;
    size_t maxQueue = 2;
    if (eventList_.size() < maxBuffSize * maxQueue) {
        return;
    }
    auto cmp = [](const std::unique_ptr<EventInfo>& a, const std::unique_ptr<EventInfo>& b) {
        return a->eventTimestamp_ < b->eventTimestamp_;
    };
    std::sort(eventList_.begin(), eventList_.end(), cmp);

    auto endOfList = eventList_.begin() + maxBuffSize;
    for (auto itor = eventList_.begin(); itor != endOfList; itor++) {
        EventInfo* event = itor->get();
        eventTimestamp_ = event->eventTimestamp_;
        eventCpu_ = event->eventCpu_;
        eventPid_ = event->eventPid_;
        eventTid_ = event->eventTid_;
        comm_ = event->common_;
        DealEvent(event->cpuDetail_);
        itor->reset();
    }
    eventList_.erase(eventList_.begin(), endOfList);
}
void HtraceEventParser::FilterAllEvents()
{
    auto cmp = [](const std::unique_ptr<EventInfo>& a, const std::unique_ptr<EventInfo>& b) {
        return a->eventTimestamp_ < b->eventTimestamp_;
    };
    std::sort(eventList_.begin(), eventList_.end(), cmp);
    size_t maxBuffSize = 1000 * 1000;

    while (eventList_.size()) {
        int size = std::min(maxBuffSize, eventList_.size());
        auto endOfList = eventList_.begin() + size;
        for (auto itor = eventList_.begin(); itor != endOfList; itor++) {
            EventInfo* event = itor->get();
            eventTimestamp_ = event->eventTimestamp_;
            eventCpu_ = event->eventCpu_;
            eventPid_ = event->eventPid_;
            eventTid_ = event->eventTid_;
            comm_ = event->common_;
            DealEvent(event->cpuDetail_);
                itor->reset();
        }
        eventList_.erase(eventList_.begin(), endOfList);
    }
    eventList_.clear();
    streamFilters_->cpuFilter_->Finish();
    traceDataCache_->dataDict_.Finish();
    traceDataCache_->UpdataZeroThreadInfo();
}
void HtraceEventParser::Clear() const
{
    streamFilters_->binderFilter_->Clear();
    streamFilters_->sliceFilter_->Clear();
    streamFilters_->cpuFilter_->Clear();
    streamFilters_->irqFilter_->Clear();
    streamFilters_->cpuMeasureFilter_->Clear();
    streamFilters_->threadMeasureFilter_->Clear();
    streamFilters_->threadFilter_->Clear();
    streamFilters_->processMeasureFilter_->Clear();
    streamFilters_->processFilterFilter_->Clear();
    streamFilters_->symbolsFilter_->Clear();
    streamFilters_->clockEnableFilter_->Clear();
    streamFilters_->clockDisableFilter_->Clear();
    streamFilters_->clkRateFilter_->Clear();
    streamFilters_->clkDisableFilter_->Clear();
    streamFilters_->binderFilter_->Clear();
    streamFilters_->sysEventMemMeasureFilter_->Clear();
    streamFilters_->sysEventVMemMeasureFilter_->Clear();
}
} // namespace TraceStreamer
} // namespace SysTuning
