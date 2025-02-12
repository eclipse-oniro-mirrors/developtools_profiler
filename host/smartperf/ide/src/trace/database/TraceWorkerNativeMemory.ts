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

class TraceWorkerNativeMemory {
    selectTotalSize = 0;
    selectTotalCount = 0;
    stackCount = 0;
    DATA_DICT: Map<number, string> = new Map<number, string>();
    HEAP_FRAME_DATA: Array<HeapTreeDataBean> = [];
    HEAP_FRAME_STACK: Map<number, NativeHookCallInfo> = new Map<number, NativeHookCallInfo>();

    initNativeMemory(queryFunc: Function) {
        this.clearAll()
        let dict = queryFunc("queryDataDICT", `select * from data_dict;`)
        dict.map((d: any) => this.DATA_DICT.set(d['id'], d['data']));
        let res = queryFunc("queryHeapAllTable", `select count(*) as count from native_hook_frame `, {})
        let count = 0;
        if (res != undefined && res.length > 0 && (res[0] as any).count != undefined) {
            count = (res[0] as any).count;
        }
        if (count > 0) {
            let pageSize = 300000;
            let pages = Math.ceil(count / pageSize);
            for (let i = 0; i < pages; i++) {
                let arr = queryFunc("queryHeapAllTable", `select h.symbol_id as symbolId, h.file_id as fileId, h.depth, h.eventId 
                    from native_hook_frame h limit $limit offset $offset`, {$limit: pageSize, $offset: i * pageSize});
                this.HEAP_FRAME_DATA = this.HEAP_FRAME_DATA.concat(arr);
            }
        }
        this.HEAP_FRAME_DATA.map((frame) => {
            frame.AllocationFunction = this.DATA_DICT.get(frame.symbolId)
            frame.MoudleName = this.DATA_DICT.get(frame.fileId)
            let frameEventId = parseInt(frame.eventId);
            let target = new NativeHookCallInfo();
            target.id = frame.eventId + "_" + frame.depth;
            target.eventId = frameEventId;
            target.depth = frame.depth;
            target.count = 1;
            let sym_arr = frame.AllocationFunction?.split("/");
            let lib_arr = frame.MoudleName?.split("/");
            target.symbol = sym_arr![sym_arr!.length - 1];
            target.symbolId = frame.symbolId;
            target.library = lib_arr![lib_arr!.length - 1];
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

    resolvingAction(paramMap: Map<string, any>): Array<NativeHookCallInfo | NativeMemory> {
        let actionType = paramMap.get("actionType");
        if (actionType == "call-info") {
            return this.resolvingActionCallInfo(paramMap);
        } else if(actionType == "native-memory"){
            return this.resolvingActionNativeMemory(paramMap);
        } else if(actionType == "memory-stack"){
            return this.resolvingActionNativeMemoryStack(paramMap);
        }else{
            return []
        }
    }

    resolvingActionNativeMemoryStack(paramMap: Map<string, any>){
        let eventId = paramMap.get("eventId");
        let frameArr = this.HEAP_FRAME_DATA.filter((frame) => parseInt(frame.eventId) == eventId);
        let arr: Array<NativeHookCallInfo> = [];
        frameArr.map((frame) => {
            let target = new NativeHookCallInfo();
            target.eventId = parseInt(frame.eventId);
            target.depth = frame.depth;
            let sym_arr = frame.AllocationFunction?.split("/");
            let lib_arr = frame.MoudleName?.split("/");
            target.symbol = sym_arr![sym_arr!.length - 1];
            target.library = lib_arr![lib_arr!.length - 1];
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
            let filterNative = this.getTypeFromIndex(parseInt(filterEventType), item,statisticsSelection)
            return filterAllocation && filterNative
        })
        let frameMap = new Map<number, NativeHookCallInfo>();
        filter.map((r) => {
            let callStack = this.HEAP_FRAME_STACK.get(r.eventId);
            if (callStack != null && callStack != undefined) {
                frameMap.set(r.eventId, callStack);
            }
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
            memory.heapSizeUnit = this.getByteWithUnit(hook.heapSize);
            memory.addr = "0x" + hook.addr;
            memory.startTs = hook.startTs;
            memory.timestamp = this.getTimeString(hook.startTs);
            memory.state = (hook.endTs > leftNs && hook.endTs <= rightNs) ? "Freed" : "Existing";
            memory.threadId = hook.tid;
            memory.threadName = hook.threadName;
            (memory as any).isSelected = hook.isSelected;
            let frame = frameMap.get(hook.eventId);
            if (frame != null && frame != undefined) {
                memory.symbol = frame.symbol;
                memory.library = frame.library;
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
                map.set(r.eventId, JSON.parse(JSON.stringify(callStack)))
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
                    if (arr[i].children.length > 0) {
                        this.mergeTree(<NativeHookCallInfo>arr[i].children[0], arr[0]);
                    } else {
                        arr[0].size += arr[i].size;
                        arr[0].heapSizeStr = `${this.getByteWithUnit(arr[0]!.size)}`;
                        arr[0].heapPercent = `${(arr[0]!.size / this.selectTotalSize * 100).toFixed(1)}%`
                    }
                }
            }
            arr[0].count = arr.length;
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
                tidCall!.heapSizeStr = `${this.getByteWithUnit(tidCall!.size)}`;
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
                tidCall.heapSizeStr = `${this.getByteWithUnit(tidCall!.size)}`;
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
        src.heapSizeStr = `${this.getByteWithUnit(src!.size)}`;
        src.heapPercent = `${(src!.size / this.selectTotalSize * 100).toFixed(1)}%`
        if (len == 0) {
            target.pid = src.id;
            src.children.push(target);
        } else {
            let index = src.children.findIndex((hook) => hook.symbol == target.symbol && hook.depth == target.depth);
            if (index != -1) {
                let srcChild = <NativeHookCallInfo>src.children[index];
                srcChild.count += 1;
                srcChild!.countValue = `${srcChild.count}`
                srcChild!.countPercent = `${(srcChild!.count / this.selectTotalCount * 100).toFixed(1)}%`
                if (target.children.length > 0) {
                    this.mergeTree(<NativeHookCallInfo>target.children[0], <NativeHookCallInfo>srcChild)
                } else {
                    srcChild.size += target.size;
                    srcChild.heapSizeStr = `${this.getByteWithUnit(src!.size)}`;
                    srcChild.heapPercent = `${(srcChild!.size / this.selectTotalSize * 100).toFixed(1)}%`
                }
            } else {
                target.pid = src.id;
                src.children.push(target)
            }
        }
    }

    traverseTree(stack: NativeHookCallInfo, hook: NativeHookStatistics) {
        stack.count = 1;
        stack.countValue = `${stack.count}`
        stack.countPercent = `${(stack!.count / this.selectTotalCount * 100).toFixed(1)}%`
        stack.size = hook.heapSize;
        stack.threadId = hook.tid;
        stack.threadName = hook.threadName;
        stack.heapSizeStr = `${this.getByteWithUnit(stack!.size)}`;
        stack.heapPercent = `${(stack!.size / this.selectTotalSize * 100).toFixed(1)}%`;
        if (stack.children.length > 0) {
            stack.children.map((child) => {
                this.traverseTree(child as NativeHookCallInfo, hook);
            })
        }
    }

    getTypeFromIndex(indexOf: number, item: NativeHookStatistics,statisticsSelection:Array<StatisticsSelection>): boolean {
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
                } else if(selectionElement.memoryTap.indexOf("Mmap") != -1){
                    return item.eventType == "MmapEvent" && item.heapSize == selectionElement.max
                } else {
                    return item.subType == selectionElement.memoryTap && item.heapSize == selectionElement.max
                }
            }
        }
        return false;
    }

    public getByteWithUnit(bytes: number): string {
        if (bytes < 0) {
            return "-" + this.getByteWithUnit(Math.abs(bytes))
        }
        let currentBytes = bytes
        let kb1 = 1 << 10;
        let mb1 = 1 << 10 << 10;
        let gb1 = 1 << 10 << 10 << 10; // 1 gb
        let res = ""
        if (currentBytes > gb1) {
            res += (currentBytes / gb1).toFixed(2) + " Gb";
        } else if (currentBytes > mb1) {
            res += (currentBytes / mb1).toFixed(2) + " Mb";
        } else if (currentBytes > kb1) {
            res += (currentBytes / kb1).toFixed(2) + " Kb";
        } else {
            res += Math.round(currentBytes) + " byte";
        }
        return res
    }

    public getTimeString(ns: number): string {
        let currentNs = ns
        let hour1 = 3600_000_000_000
        let minute1 = 60_000_000_000
        let second1 = 1_000_000_000;
        let millisecond1 = 1_000_000;
        let microsecond1 = 1_000;
        let res = "";
        if (currentNs >= hour1) {
            res += Math.floor(currentNs / hour1) + "h ";
            currentNs = currentNs - Math.floor(currentNs / hour1) * hour1
        }
        if (currentNs >= minute1) {
            res += Math.floor(currentNs / minute1) + "m ";
            currentNs = currentNs - Math.floor(ns / minute1) * minute1
        }
        if (currentNs >= second1) {
            res += Math.floor(currentNs / second1) + "s ";
            currentNs = currentNs - Math.floor(currentNs / second1) * second1
        }
        if (currentNs >= millisecond1) {
            res += Math.floor(currentNs / millisecond1) + "ms ";
            currentNs = currentNs - Math.floor(currentNs / millisecond1) * millisecond1
        }
        if (currentNs >= microsecond1) {
            res += Math.floor(currentNs / microsecond1) + "μs ";
            currentNs = currentNs - Math.floor(currentNs / microsecond1) * microsecond1
        }
        if (currentNs > 0) {
            res += currentNs + "ns ";
        }
        if (res == "") {
            res = ns + "";
        }
        return res
    }

    clearAll() {
        this.DATA_DICT.clear();
        this.HEAP_FRAME_DATA = [];
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

let nativeMemoryWorker = new TraceWorkerNativeMemory()

class HeapTreeDataBean {
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

class NativeHookStatistics {
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

class NativeHookCallInfo extends ChartStruct {
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

class NativeMemory {
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
    threadId:number = 0;
    threadName:string = "";
}

class StatisticsSelection{
    memoryTap:string = "";
    max:number = 0;
}