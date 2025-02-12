/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

import {ChartStruct, convertJSON, getByteWithUnit, getTimeString, LogicHandler} from "./ProcedureLogicWorkerCommon.js";


export class ProcedureLogicWorkerNativeMemory extends LogicHandler {
    selectTotalSize = 0;
    selectTotalCount = 0;
    stackCount = 0;
    DATA_DICT: Map<number, string> = new Map<number, string>();
    HEAP_FRAME_MAP: Map<number,Array<HeapTreeDataBean>> = new Map<number, Array<HeapTreeDataBean>>();
    HEAP_FRAME_STACK: Map<number, NativeHookCallInfo> = new Map<number, NativeHookCallInfo>();
    NATIVE_MEMORY_DATA: Array<NativeEvent> = [];
    currentEventId: string = ""

    handle(data: any): void {
        this.currentEventId = data.id
        if (data && data.type) {
            switch (data.type) {
                case "native-memory-init":
                    this.clearAll();
                    this.initDataDict();
                    break
                case "native-memory-queryDataDICT":
                    let dict = convertJSON(data.params.list) || []
                    dict.map((d: any) => this.DATA_DICT.set(d['id'], d['data']));
                    this.initNMChartData();
                    break;
                case "native-memory-queryNMChartData":
                    this.NATIVE_MEMORY_DATA = convertJSON(data.params.list) || [];
                    this.initNMFrameData();
                    break;
                case "native-memory-queryNMFrameData":
                    let arr = convertJSON(data.params.list) || [];
                    this.initNMStack(arr);
                    arr = [];
                    self.postMessage({
                        id: data.id,
                        action: "native-memory-init",
                        results: []
                    });
                    break;
                case "native-memory-action":
                    if (data.params) {
                        // @ts-ignore
                        self.postMessage({
                            id: data.id,
                            action: data.action,
                            results: this.resolvingAction(data.params)
                        });
                    }
                    break;
            }
        }
    }

    queryData(queryName: string, sql: string, args: any) {
        self.postMessage({
            id: this.currentEventId,
            type: queryName,
            isQuery: true,
            args: args,
            sql: sql
        })
    }

    initDataDict() {
        this.queryData("native-memory-queryDataDICT", `select * from data_dict;`, {})
    }

    initNMChartData() {
        this.queryData("native-memory-queryNMChartData", `
            select * from (
                select 
                    h.start_ts - t.start_ts as startTime,
                    h.heap_size as heapSize,
                    h.event_type as eventType
                from native_hook h ,trace_range t
                where h.start_ts >= t.start_ts and h.start_ts <= t.end_ts and (h.event_type = 'AllocEvent' or h.event_type = 'MmapEvent')
                union
                select 
                    h.end_ts - t.start_ts as startTime,
                    h.heap_size as heapSize,
                    (case when h.event_type = 'AllocEvent' then 'FreeEvent' else 'MunmapEvent' end) as eventType
                from native_hook h ,trace_range t
                where h.start_ts >= t.start_ts and h.start_ts <= t.end_ts
                    and (h.event_type = 'AllocEvent' or h.event_type = 'MmapEvent')
                    and h.end_ts not null ) order by startTime;
        `, {})
    }

    initNMFrameData() {
        this.queryData("native-memory-queryNMFrameData", `
            select h.symbol_id as symbolId, h.file_id as fileId, h.depth, h.callchain_id as eventId 
                    from native_hook_frame h
        `, {})
    }

    initNMStack(frameArr:Array<HeapTreeDataBean>){
        frameArr.map((frame) => {
            let sym_arr = (this.DATA_DICT.get(frame.symbolId) ?? "").split("/");
            let lib_arr = (this.DATA_DICT.get(frame.fileId) ?? "").split("/");
            frame.AllocationFunction = sym_arr![sym_arr!.length - 1];
            frame.MoudleName = lib_arr![lib_arr!.length - 1];
            let frameEventId = parseInt(frame.eventId);
            if(this.HEAP_FRAME_MAP.has(frameEventId)){
                this.HEAP_FRAME_MAP.get(frameEventId)!.push(frame);
            }else{
                this.HEAP_FRAME_MAP.set(frameEventId,[frame])
            }
            let target = new NativeHookCallInfo();
            target.id = frame.eventId + "_" + frame.depth;
            target.eventId = frameEventId;
            target.depth = frame.depth;
            target.count = 1;
            target.symbol = frame.AllocationFunction;
            target.symbolId = frame.symbolId;
            target.library = frame.MoudleName;
            target.title = `[ ${target.symbol} ]  ${target.library}`;
            target.type = (target.library.endsWith(".so.1") || target.library.endsWith(".dll") || target.library.endsWith(".so")) ? 0 : 1;
            if (this.HEAP_FRAME_STACK.has(frameEventId)) {
                let src = this.HEAP_FRAME_STACK.get(frameEventId);
                this.listToTree(target, src!);
            } else {
                this.HEAP_FRAME_STACK.set(frameEventId, target);
            }
        })
    }

    resolvingAction(paramMap: Map<string, any>): Array<NativeHookCallInfo | NativeMemory | HeapStruct> {
        let actionType = paramMap.get("actionType");
        if (actionType == "call-info") {
            return this.resolvingActionCallInfo(paramMap);
        } else if (actionType == "native-memory") {
            return this.resolvingActionNativeMemory(paramMap);
        } else if (actionType == "memory-stack") {
            return this.resolvingActionNativeMemoryStack(paramMap);
        } else if (actionType == "memory-chart") {
            return this.resolvingActionNativeMemoryChartData(paramMap);
        } else {
            return []
        }
    }

    resolvingActionNativeMemoryChartData(paramMap: Map<string, any>): Array<HeapStruct> {
        let nativeMemoryType: number = paramMap.get("nativeMemoryType") as number;
        let chartType: number = paramMap.get("chartType") as number;
        let totalNS: number = paramMap.get("totalNS") as number;
        let arr: Array<HeapStruct> = [];
        let source: Array<NativeEvent> = [];
        if (nativeMemoryType == 0) {
            source = this.NATIVE_MEMORY_DATA;
        } else if (nativeMemoryType == 1) {
            this.NATIVE_MEMORY_DATA.map((ne) => {
                if (ne.eventType == 'AllocEvent' || ne.eventType == 'FreeEvent') {
                    source.push(ne);
                }
            })
        } else {
            this.NATIVE_MEMORY_DATA.map((ne) => {
                if (ne.eventType == 'MmapEvent' || ne.eventType == 'MunmapEvent') {
                    source.push(ne);
                }
            })
        }
        if (source.length > 0) {
            let first = new HeapStruct();
            first.startTime = source[0].startTime;
            first.eventType = source[0].eventType;
            if (first.eventType == "AllocEvent" || first.eventType == "MmapEvent") {
                first.heapsize = chartType == 1 ? 1 : source[0].heapSize;
            } else {
                first.heapsize = chartType == 1 ? -1 : (0 - source[0].heapSize);
            }
            arr.push(first);
            let max = first.heapsize;
            let min = first.heapsize;
            for (let i = 1, len = source.length; i < len; i++) {
                let heap = new HeapStruct();
                heap.startTime = source[i].startTime;
                heap.eventType = source[i].eventType;
                arr[i - 1].dur = heap.startTime! - arr[i - 1].startTime!;
                if (i == len - 1) {
                    heap.dur = totalNS - heap.startTime!;
                }
                if (heap.eventType == "AllocEvent" || heap.eventType == "MmapEvent") {
                    if (chartType == 1) {
                        heap.heapsize = arr[i - 1].heapsize! + 1;
                    } else {
                        heap.heapsize = arr[i - 1].heapsize! + source[i].heapSize;
                    }
                } else {
                    if (chartType == 1) {
                        heap.heapsize = arr[i - 1].heapsize! - 1;
                    } else {
                        heap.heapsize = arr[i - 1].heapsize! - source[i].heapSize;
                    }
                }
                if (heap.heapsize > max) {
                    max = heap.heapsize;
                }
                if (heap.heapsize < min) {
                    min = heap.heapsize;
                }
                arr.push(heap);
            }
            arr.map((heap) => {
                heap.maxHeapSize = max;
                heap.minHeapSize = min;
            })
        }
        return arr;
    }

    resolvingActionNativeMemoryStack(paramMap: Map<string, any>) {
        let eventId = paramMap.get("eventId");
        let frameArr = this.HEAP_FRAME_MAP.get(eventId) || [];
        let arr: Array<NativeHookCallInfo> = [];
        frameArr.map((frame) => {
            let target = new NativeHookCallInfo();
            target.eventId = parseInt(frame.eventId);
            target.depth = frame.depth;
            target.symbol = frame.AllocationFunction ?? "";
            target.library = frame.MoudleName ?? "";
            target.title = `[ ${target.symbol} ]  ${target.library}`;
            target.type = (target.library.endsWith(".so.1") || target.library.endsWith(".dll") || target.library.endsWith(".so")) ? 0 : 1;
            arr.push(target);
        })
        return arr;
    }

    resolvingActionNativeMemory(paramMap: Map<string, any>): Array<NativeMemory> {
        let dataSource = paramMap.get("data") as Array<NativeHookStatistics>;
        let filterAllocType = paramMap.get("filterAllocType");
        let filterEventType = paramMap.get("filterEventType");
        let leftNs = paramMap.get("leftNs");
        let rightNs = paramMap.get("rightNs");
        let statisticsSelection = paramMap.get("statisticsSelection");
        let filter = dataSource.filter((item) => {
            let filterAllocation = true
            if (filterAllocType == "1") {
                filterAllocation = item.startTs >= leftNs && item.startTs <= rightNs
                    && (item.endTs > rightNs || item.endTs == 0 || item.endTs == null)
            } else if (filterAllocType == "2") {
                filterAllocation = item.startTs >= leftNs && item.startTs <= rightNs
                    && item.endTs <= rightNs && item.endTs != 0 && item.endTs != null;
            }
            let filterNative = this.getTypeFromIndex(parseInt(filterEventType), item, statisticsSelection)
            return filterAllocation && filterNative
        })
        let data: Array<NativeMemory> = [];
        for (let i = 0, len = filter.length; i < len; i++) {
            let hook = filter[i];
            let memory = new NativeMemory();
            memory.index = i;
            memory.eventId = hook.eventId;
            memory.eventType = hook.eventType;
            memory.subType = hook.subType;
            memory.heapSize = hook.heapSize;
            memory.endTs = hook.endTs;
            memory.heapSizeUnit = getByteWithUnit(hook.heapSize);
            memory.addr = "0x" + hook.addr;
            memory.startTs = hook.startTs;
            memory.timestamp = getTimeString(hook.startTs);
            memory.state = (hook.endTs > leftNs && hook.endTs <= rightNs) ? "Freed" : "Existing";
            memory.threadId = hook.tid;
            memory.threadName = hook.threadName;
            (memory as any).isSelected = hook.isSelected;
            let arr = this.HEAP_FRAME_MAP.get(hook.eventId) || []
            let frame = Array.from(arr).reverse().find((item) => !((item.MoudleName ?? "").includes("libc++") || (item.MoudleName ?? "").includes("musl")))
            if (frame != null && frame != undefined) {
                memory.symbol = frame.AllocationFunction ?? "";
                memory.library = frame.MoudleName ?? "Unknown Path";
            }
            data.push(memory);
        }
        return data
    }

    resolvingActionCallInfo(paramMap: Map<string, any>): Array<NativeHookCallInfo> {
        let dataSource = paramMap.get("data") as Array<NativeHookStatistics>;
        let filterAllocType = paramMap.get("filterAllocType");
        let filterEventType = paramMap.get("filterEventType");
        let leftNs = paramMap.get("leftNs");
        let rightNs = paramMap.get("rightNs");
        let filter: Array<NativeHookStatistics> = [];
        dataSource.map((item) => {
            let filterAllocation = true;
            let filterNative = true;
            if (filterAllocType == "1") {
                filterAllocation = item.startTs >= leftNs && item.startTs <= rightNs
                    && (item.endTs > rightNs || item.endTs == 0 || item.endTs == null)
            } else if (filterAllocType == "2") {
                filterAllocation = item.startTs >= leftNs && item.startTs <= rightNs
                    && item.endTs <= rightNs && item.endTs != 0 && item.endTs != null;
            }
            if (filterEventType == "1") {
                filterNative = item.eventType == "AllocEvent"
            } else if (filterEventType == "2") {
                filterNative = item.eventType == "MmapEvent"
            }
            if (filterAllocation && filterNative) {
                filter.push(item);
            }
        })
        this.selectTotalSize = 0;
        this.selectTotalCount = filter.length
        let map = new Map<number, NativeHookCallInfo>();
        filter.map((r) => {
            this.selectTotalSize += r.heapSize;
        });
        filter.map((r) => {
            let callStack = this.HEAP_FRAME_STACK.get(r.eventId);
            if (callStack != null && callStack != undefined) {
                this.traverseTree(callStack, r);
                if (map.has(r.eventId)) {
                    let stack = map.get(r.eventId)
                    this.traverseSampleTree(stack!, r);
                } else {
                    map.set(r.eventId, JSON.parse(JSON.stringify(callStack)))
                }
            }
        })
        let groupMap = new Map<string, Array<NativeHookCallInfo>>();
        for (let value of map.values()) {
            let key = value.threadId + "_" + value.symbol;
            if (groupMap.has(key)) {
                groupMap.get(key)!.push(value);
            } else {
                let arr: Array<NativeHookCallInfo> = [];
                arr.push(value);
                groupMap.set(key, arr);
            }
        }
        let stackArr = Array.from(groupMap.values());
        let data: Array<NativeHookCallInfo> = [];
        for (let arr of stackArr) {
            if (arr.length > 1) {
                for (let i = 1; i < arr.length; i++) {
                    arr[0].count += arr[i].count;
                    if (arr[i].children.length > 0) {
                        this.mergeTree(<NativeHookCallInfo>arr[i].children[0], arr[0]);
                    } else {
                        arr[0].size += arr[i].size;
                        arr[0].heapSizeStr = `${getByteWithUnit(arr[0]!.size)}`;
                        arr[0].heapPercent = `${(arr[0]!.size / this.selectTotalSize * 100).toFixed(1)}%`
                    }
                }
            } else {
                arr[0].count = arr[0].count;
            }
            arr[0]!.countValue = `${arr[0].count}`
            arr[0]!.countPercent = `${(arr[0]!.count / this.selectTotalCount * 100).toFixed(1)}%`
            data.push(arr[0]);
        }
        return this.groupByWithTid(data);
    }

    groupByWithTid(data: Array<NativeHookCallInfo>): Array<NativeHookCallInfo> {
        let tidMap = new Map<number, NativeHookCallInfo>();
        for (let call of data) {
            call.pid = "tid_" + call.threadId;
            if (tidMap.has(call.threadId)) {
                let tidCall = tidMap.get(call.threadId);
                tidCall!.size += call.size;
                tidCall!.heapSizeStr = `${getByteWithUnit(tidCall!.size)}`;
                tidCall!.heapPercent = `${(tidCall!.size / this.selectTotalSize * 100).toFixed(1)}%`
                tidCall!.count += call.count;
                tidCall!.countValue = `${tidCall!.count}`
                tidCall!.countPercent = `${(tidCall!.count / this.selectTotalCount * 100).toFixed(1)}%`
                tidCall!.children.push(call);
            } else {
                let tidCall = new NativeHookCallInfo();
                tidCall.id = "tid_" + call.threadId;
                tidCall.count = call.count;
                tidCall!.countValue = `${call.count}`
                tidCall!.countPercent = `${(tidCall!.count / this.selectTotalCount * 100).toFixed(1)}%`
                tidCall.size = call.size;
                tidCall.heapSizeStr = `${getByteWithUnit(tidCall!.size)}`;
                tidCall!.heapPercent = `${(tidCall!.size / this.selectTotalSize * 100).toFixed(1)}%`
                tidCall.title = (call.threadName == null ? 'Thread' : call.threadName) + " [ " + call.threadId + " ]";
                tidCall.symbol = tidCall.title;
                tidCall.type = -1;
                tidCall.children.push(call);
                tidMap.set(call.threadId, tidCall);
            }
        }
        let showData = Array.from(tidMap.values())
        return showData;
    }

    mergeTree(target: NativeHookCallInfo, src: NativeHookCallInfo) {
        let len = src.children.length;
        src.size += target.size;
        src.heapSizeStr = `${getByteWithUnit(src!.size)}`;
        src.heapPercent = `${(src!.size / this.selectTotalSize * 100).toFixed(1)}%`
        if (len == 0) {
            target.pid = src.id;
            src.children.push(target);
        } else {
            let index = src.children.findIndex((hook) => hook.symbol == target.symbol && hook.depth == target.depth);
            if (index != -1) {
                let srcChild = <NativeHookCallInfo>src.children[index];
                srcChild.count += target.count;
                srcChild!.countValue = `${srcChild.count}`
                srcChild!.countPercent = `${(srcChild!.count / this.selectTotalCount * 100).toFixed(1)}%`
                if (target.children.length > 0) {
                    this.mergeTree(<NativeHookCallInfo>target.children[0], <NativeHookCallInfo>srcChild)
                } else {
                    srcChild.size += target.size;
                    srcChild.heapSizeStr = `${getByteWithUnit(src!.size)}`;
                    srcChild.heapPercent = `${(srcChild!.size / this.selectTotalSize * 100).toFixed(1)}%`
                }
            } else {
                target.pid = src.id;
                src.children.push(target)
            }
        }
    }

    traverseSampleTree(stack: NativeHookCallInfo, hook: NativeHookStatistics) {
        stack.count += 1;
        stack.countValue = `${stack.count}`
        stack.countPercent = `${(stack.count / this.selectTotalCount * 100).toFixed(1)}%`
        stack.size += hook.heapSize;
        stack.threadId = hook.tid;
        stack.threadName = hook.threadName;
        stack.heapSizeStr = `${getByteWithUnit(stack.size)}`;
        stack.heapPercent = `${(stack.size / this.selectTotalSize * 100).toFixed(1)}%`;
        if (stack.children.length > 0) {
            stack.children.map((child) => {
                this.traverseSampleTree(child as NativeHookCallInfo, hook);
            })
        }
    }

    traverseTree(stack: NativeHookCallInfo, hook: NativeHookStatistics) {
        stack.count = 1;
        stack.countValue = `${stack.count}`
        stack.countPercent = `${(stack!.count / this.selectTotalCount * 100).toFixed(1)}%`
        stack.size = hook.heapSize;
        stack.threadId = hook.tid;
        stack.threadName = hook.threadName;
        stack.heapSizeStr = `${getByteWithUnit(stack!.size)}`;
        stack.heapPercent = `${(stack!.size / this.selectTotalSize * 100).toFixed(1)}%`;
        if (stack.children.length > 0) {
            stack.children.map((child) => {
                this.traverseTree(child as NativeHookCallInfo, hook);
            })
        }
    }

    getTypeFromIndex(indexOf: number, item: NativeHookStatistics, statisticsSelection: Array<StatisticsSelection>): boolean {
        if (indexOf == -1) {
            return false;
        }
        if (indexOf < 3) {
            if (indexOf == 0) {
                return true
            } else if (indexOf == 1) {
                return item.eventType == "AllocEvent"
            } else if (indexOf == 2) {
                return item.eventType == "MmapEvent"
            }
        } else if (indexOf - 3 < statisticsSelection.length) {
            let selectionElement = statisticsSelection[indexOf - 3];
            if (selectionElement.memoryTap != undefined && selectionElement.max != undefined) {
                if (selectionElement.memoryTap.indexOf("Malloc") != -1) {
                    return item.eventType == "AllocEvent" && item.heapSize == selectionElement.max
                } else if (selectionElement.memoryTap.indexOf("Mmap") != -1) {
                    return item.eventType == "MmapEvent" && item.heapSize == selectionElement.max
                } else {
                    return item.subType == selectionElement.memoryTap && item.heapSize == selectionElement.max
                }
            }
        }
        return false;
    }

    clearAll() {
        this.DATA_DICT.clear();
        this.HEAP_FRAME_MAP.clear();
        this.NATIVE_MEMORY_DATA = [];
        this.HEAP_FRAME_STACK.clear();
    }

    listToTree(target: NativeHookCallInfo, src: NativeHookCallInfo) {
        if (target.depth == src.depth + 1) {
            target.pid = src.id;
            src.children.push(target)
        } else {
            if (src.children.length > 0) {
                this.listToTree(target, <NativeHookCallInfo>src.children[0]);
            }
        }
    }
}

export class HeapTreeDataBean {
    MoudleName: string | undefined
    AllocationFunction: string | undefined
    symbolId: number = 0
    fileId: number = 0
    startTs: number = 0
    endTs: number = 0
    eventType: string | undefined
    depth: number = 0
    heapSize: number = 0
    eventId: string = ""
}

export class NativeHookStatistics {
    eventId: number = 0;
    eventType: string = "";
    subType: string = "";
    subTypeId: number = 0;
    heapSize: number = 0;
    addr: string = "";
    startTs: number = 0;
    endTs: number = 0;
    sumHeapSize: number = 0;
    max: number = 0;
    count: number = 0;
    tid: number = 0;
    threadName: string = "";
    isSelected: boolean = false;
}

export class NativeHookCallInfo extends ChartStruct {
    id: string = "";
    pid: string | undefined;
    library: string = "";
    symbolId: number = 0;
    title: string = "";
    count: number = 0;
    countValue: string = ""
    countPercent: string = "";
    type: number = 0;
    heapSize: number = 0;
    heapPercent: string = "";
    heapSizeStr: string = "";
    eventId: number = 0;
    threadId: number = 0;
    threadName: string = "";
    isSelected: boolean = false;
}

export class NativeMemory {
    index: number = 0;
    eventId: number = 0;
    eventType: string = "";
    subType: string = "";
    addr: string = "";
    startTs: number = 0;
    endTs: number = 0;
    timestamp: string = ""
    heapSize: number = 0;
    heapSizeUnit: string = "";
    symbol: string = "";
    library: string = "";
    isSelected: boolean = false;
    state: string = "";
    threadId: number = 0;
    threadName: string = "";
}

export class HeapStruct {
    startTime: number | undefined
    endTime: number | undefined
    dur: number | undefined
    eventType: string | undefined
    heapsize: number | undefined
    maxHeapSize: number = 0
    minHeapSize: number = 0
}

export class NativeEvent {
    startTime: number = 0;
    heapSize: number = 0;
    eventType: string = "";
}

export class StatisticsSelection {
    memoryTap: string = "";
    max: number = 0;
}