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

import {
    convertJSON, getByteWithUnit,
    getProbablyTime,
    getTimeString,
    LogicHandler,
    MerageBean,
    merageBeanDataSplit,
    postMessage,
    setFileName
} from "./ProcedureLogicWorkerCommon.js";

export let FILE_TYPE_MAP = {
    '0': 'OPEN',
    '1': 'CLOSE',
    '2': 'READ',
    '3': 'WRITE',
};

export let DISKIO_TYPE_MAP = {
    '0': 'OPEN',
    '1': 'CLOSE',
    '2': 'READ',
    '3': 'WRITE',
};

export let VM_TYPE_MAP = {
    '1': 'File Backed In',
    '2': 'Page Cache Hit',
    '3': 'Swap From Zram',
    '4': 'Swap From Disk',
    '5': 'Zero Fill Page',
    '6': 'Zero FAKE Page',
    '7': 'Copy On Write',
};

export class ProcedureLogicWorkerFileSystem extends LogicHandler {
    tab:string = "";
    data_dict: Map<number, string> = new Map<number, string>();
    currentEventId: string = ""
    currentTreeMapData: any = {}
    samplesData: FileSample[] = []
    splitMapData: any = {}
    currentTreeList: any[] = []
    searchValue: string = ""
    callChainsMap: Map<number, FileCallChain[]> = new Map<number, FileCallChain[]>()
    allProcess: FileMerageBean[] = []
    dataSource: FileMerageBean[] = []
    currentDataType:string = ""

    handle(data: any): void {
        this.currentEventId = data.id
        if (data && data.type) {
            switch (data.type) {
                case "fileSystem-init":
                    this.data_dict = data.params as Map<number, string>
                    this.initCallchains();
                    break
                case "fileSystem-queryCallchains":
                    let callChains = convertJSON(data.params.list) || [];
                    this.initCallChainTopDown(callChains)
                    // @ts-ignore
                    self.postMessage({id: data.id, action: data.action, results: []});
                    break;
                case "fileSystem-queryFileSamples":
                case "fileSystem-queryIoSamples":
                case "fileSystem-queryVirtualMemorySamples":
                    this.currentDataType = data.type
                    this.samplesData = convertJSON(data.params.list) || []
                    self.postMessage({
                        id: data.id, action: data.action, results: this.resolvingAction([{
                            funcName: "getCallChainsBySampleIds",
                            funcArgs: [true]
                        }])
                    });
                    break;
                case "fileSystem-action":
                    if (data.params) {
                        let filter = data.params.filter((item: any) => item.funcName == "getCurrentDataFromDb");
                        if (filter.length == 0) {
                            // @ts-ignore
                            self.postMessage({
                                id: data.id,
                                action: data.action,
                                results: this.resolvingAction(data.params)
                            });
                        } else {
                            this.resolvingAction(data.params)
                        }
                    }
                    break;
                case "fileSystem-queryStack":
                    let res = this.getStacksByCallchainId(data.params.callchainId)
                    self.postMessage({id: data.id, action: data.action, results: res})
                    break;
                case "fileSystem-queryFileSysEvents":
                    if (data.params.list) {
                        let res = convertJSON(data.params.list) || []
                        postMessage(data.id, data.action, this.supplementFileSysEvents(res, this.tab));
                    } else {
                        this.tab = data.params.tab;
                        this.queryFileSysEvents(data.params.leftNs, data.params.rightNs, data.params.typeArr, data.params.tab)
                    }
                    break;
                case "fileSystem-queryVMEvents":
                    if (data.params.list) {
                        let res = convertJSON(data.params.list) || []
                        postMessage(data.id, data.action, this.supplementVMEvents(res));
                    } else {
                        this.queryVMEvents(data.params.leftNs, data.params.rightNs, data.params.typeArr)
                    }
                    break
                case "fileSystem-queryIOEvents":
                    if (data.params.list) {
                        let res = convertJSON(data.params.list) || []
                        postMessage(data.id, data.action, this.supplementIoEvents(res));
                    } else {
                        this.queryIOEvents(data.params.leftNs, data.params.rightNs, data.params.typeArr)
                    }
                    break
            }
        }
    }

    queryFileSysEvents(leftNs: number, rightNs: number, typeArr: Array<number>, tab: string) {
        let types = Array.from(typeArr).join(",");
        let sql = "";
        if (tab == "events") {
            sql = `
            select
                A.callchain_id as callchainId,
                (A.start_ts - B.start_ts) as startTs,
                dur,
                A.type,
                ifnull(C.name,'Process') || '[' || C.pid || ']' as process,
                ifnull(D.name,'Thread') || '[' || D.tid || ']' as thread,
                first_argument as firstArg,
                second_argument as secondArg,
                third_argument as thirdArg,
                fourth_argument as fourthArg,
                return_value as returnValue,
                error_code as error
            from file_system_sample A,trace_range B
            left join process C on A.ipid = C.id
            left join thread D on A.itid = D.id
            where A.type in (${types})
            and(
                (A.end_ts - B.start_ts) between $leftNS and $rightNS
            )
            order by A.end_ts;
        `
        } else if (tab == "history") {
            sql = `
            select
                A.callchain_id as callchainId,
                (A.start_ts - B.start_ts) as startTs,
                dur,
                fd,
                A.type,
                ifnull(C.name,'Process') || '[' || C.pid || ']' as process
            from file_system_sample A,trace_range B
            left join process C on A.ipid = C.id
            where A.type in (${types})
            and fd not null
            and(
                (A.start_ts - B.start_ts) between $leftNS and $rightNS 
            )
            order by A.end_ts;
        `
        } else {
            sql = `
            select TB.callchain_id                                  as callchainId,
                (TB.start_ts - TR.start_ts)                         as startTs,
                (${rightNs} - TB.start_ts)                          as dur,
                TB.fd,
                TB.type,
                ifnull(TC.name, 'Process') || '[' || TC.pid || ']'  as process
            from (
                select fd,
                    max(case when type = 0 then A.end_ts else 0 end) as openTs,
                    max(case when type = 1 then A.end_ts else 0 end) as closeTs
                from file_system_sample A
                where type in (0, 1) and A.end_ts between $leftNS and $rightNS group by fd
                ) TA
            left join file_system_sample TB on TA.fd = TB.fd and TA.openTs = TB.end_ts
            left join process TC on TB.ipid = TC.ipid
            left join trace_range TR
            where startTs not null and TB.fd not null and TA.closeTs < TA.openTs
            order by TB.end_ts;  `
        }
        this.queryData("fileSystem-queryFileSysEvents", sql, {$leftNS: leftNs, $rightNS: rightNs})
    }

    queryVMEvents(leftNs: number, rightNs: number, typeArr: Array<number>){
        let types = Array.from(typeArr).join(",");
        let sql = `select
                A.callchain_id as callchainId,
                (A.start_ts - B.start_ts) as startTs,
                dur,
                addr as address,
                C.pid,
                T.tid,
                size,
                A.type,
                ifnull(T.name,'Thread') || '[' || T.tid || ']' as thread,
                ifnull(C.name,'Process') || '[' || C.pid || ']' as process
            from virtual_memory_sample A,trace_range B
            left join process C on A.ipid = C.id
            left join thread T on T.id = A.itid 
            where (
                (A.end_ts - B.start_ts) between $leftNS and $rightNS
            );`;
        this.queryData("fileSystem-queryVMEvents", sql, {$leftNS: leftNs, $rightNS: rightNs})
    }

    queryIOEvents(leftNs: number, rightNs: number, typeArr: Array<number>){
        let types = Array.from(typeArr).join(",");
        let sql = `select
                A.callchain_id as callchainId,
                (A.start_ts - B.start_ts) as startTs,
                latency_dur as dur,
                path,
                dur_per_4k as durPer4k,
                tier,
                size,
                A.type,
                block_number as blockNumber,
                ifnull(T.name,'Thread') || '[' || T.tid || ']' as thread,
                ifnull(C.name,'Process') || '[' || C.pid || ']' as process
            from io_latency_sample A,trace_range B
            left join process C on A.ipid = C.id
            left join thread T on T.id = A.itid 
            where (
                (A.start_ts - B.start_ts) between $leftNS and $rightNS 
                or 
                (A.start_ts + A.latency_dur - B.start_ts) between $leftNS and $rightNS
            );`;
        this.queryData("fileSystem-queryIOEvents", sql, {$leftNS: leftNs, $rightNS: rightNs})
    }

    getStacksByCallchainId(id: number) {
        let stacks = this.callChainsMap.get(id) ?? [];
        let arr: Array<Stack> = [];
        for (let s of stacks) {
            let st: Stack = new Stack()
            st.path = (this.data_dict.get(s.pathId) ?? "Unknown Path").split("/").reverse()[0];
            st.symbol = `${s.symbolsId == null ? s.ip : this.data_dict.get(s.symbolsId) ?? ''} (${st.path})`;
            st.type = (st.path.endsWith(".so.1") || st.path.endsWith(".dll") || st.path.endsWith(".so")) ? 0 : 1;
            arr.push(st);
        }
        return arr;
    }

    supplementIoEvents(res: Array<IoCompletionTimes>){
        return res.map((event) => {
            event.startTsStr = getTimeString(event.startTs)
            event.durPer4kStr = getProbablyTime(event.durPer4k)
            event.sizeStr = getByteWithUnit(event.size)
            event.durStr = getProbablyTime(event.dur)
            // @ts-ignore
            event.operation = DISKIO_TYPE_MAP[`${event.type}`]||"UNKNOW"
            let stacks = this.callChainsMap.get(event.callchainId)||[];
            if(stacks.length > 0){
                let stack = stacks[0]
                event.backtrace = [stack.symbolsId == null ? stack.ip : this.data_dict.get(stack.symbolsId) ?? "", `(${stacks.length} other frames)`];
            }else {
                event.backtrace = [];
            }
            return event
        })
    }

    supplementVMEvents(res: Array<VirtualMemoryEvent>){
        return res.map((event) => {
            event.startTsStr = getTimeString(event.startTs)
            event.sizeStr = getByteWithUnit(event.size*4096)
            event.durStr = getProbablyTime(event.dur)
            // @ts-ignore
            event.operation = VM_TYPE_MAP[`${event.type}`]||"UNKNOW"
            return event
        })
    }


    supplementFileSysEvents(res: Array<FileSysEvent>, tab: string) {
        res.map((r) => {
            let stacks = this.callChainsMap.get(r.callchainId);
            r.startTsStr = getTimeString(r.startTs);
            r.durStr = getProbablyTime(r.dur);
            if (tab == "events") {
                r.firstArg = r.firstArg ?? "0x0"
                r.secondArg = r.secondArg ?? "0x0"
                r.thirdArg = r.thirdArg ?? "0x0"
                r.fourthArg = r.fourthArg ?? "0x0"
                r.returnValue = r.returnValue ?? "0x0"
                r.error = r.error ?? "0x0"
            }
            // @ts-ignore
            r.typeStr = FILE_TYPE_MAP[`${r.type}`] ?? "";
            if (stacks && stacks.length > 0) {
                let stack = stacks[0]
                r.depth = stacks.length;
                r.symbol = stack.symbolsId == null ? stack.ip : this.data_dict.get(stack.symbolsId) ?? ""
                if (tab != "events") {
                    r.path = this.data_dict.get(stack.pathId) ?? ""
                }
                r.backtrace = [r.symbol, `(${r.depth} other frames)`];
            } else {
                r.depth = 0;
                r.symbol = "";
                r.path = "";
                r.backtrace = [];
            }
        })
        return res;
    }

    initCallchains() {
        this.clearAll()
        this.queryData("fileSystem-queryCallchains", `select callchain_id as callChainId,depth,symbols_id as symbolsId,file_path_id as pathId,ip from ebpf_callstack`, {})
    }

    queryCallchainsSamples(selectionParam: any){
        if(selectionParam.queryFuncName!=undefined){
            switch (selectionParam.queryFuncName) {
                case "fileSystem":
                    this.queryFileSamples(selectionParam)
                    break;
                case "io":
                    this.queryIOSamples(selectionParam)
                    break;
                case "virtualMemory":
                    this.queryEpbfSamples(selectionParam)
                    break;
            }
        }
    }

    queryFileSamples(selectionParam: any) {
        let sql = '';
        if (selectionParam.fileSystemType != undefined && selectionParam.fileSystemType.length > 0) {
            sql += " and s.type in ("
            sql += selectionParam.fileSystemType.join(",")
            sql += ")"
        }
        this.queryData("fileSystem-queryFileSamples", `select s.callchain_id as callChainId,h.tid,h.name as threadName,s.dur,s.type,p.pid,p.name as processName from file_system_sample s,trace_range t 
left join process p on p.id = s.ipid  
left join thread h on h.id = s.itid 
where s.end_ts between $startTime + t.start_ts and $endTime + t.start_ts ${sql} and callchain_id != -1;`
            , {$startTime: selectionParam.leftNs, $endTime: selectionParam.rightNs})

    }

    queryIOSamples(selectionParam: any){
        let sql = '';
        this.queryData("fileSystem-queryIoSamples", `select s.callchain_id as callChainId,h.tid,h.name as threadName,s.latency_dur as dur,s.type,p.pid,p.name as processName from io_latency_sample s,trace_range t
left join process p on p.id = s.ipid
left join thread h on h.id = s.itid
where s.end_ts between $startTime + t.start_ts and $endTime + t.start_ts ${sql} and callchain_id != -1;`
            , {$startTime: selectionParam.leftNs, $endTime: selectionParam.rightNs})
    }

    queryEpbfSamples(selectionParam: any){
        let sql = '';
        this.queryData("fileSystem-queryVirtualMemorySamples", `select s.callchain_id as callChainId,h.tid,h.name as threadName,s.dur,s.type,p.pid,p.name as processName from virtual_memory_sample s,trace_range t 
left join process p on p.id = s.ipid  
left join thread h on h.id = s.itid 
where s.end_ts between $startTime + t.start_ts and $endTime + t.start_ts ${sql} and callchain_id != -1;`
            , {$startTime: selectionParam.leftNs, $endTime: selectionParam.rightNs})
    }

    initCallChainTopDown(list: any[]) {
        list.forEach((callchain: FileCallChain) => {
            if (this.callChainsMap.has(callchain.callChainId)) {
                this.callChainsMap.get(callchain.callChainId)!.push(callchain)
            } else {
                this.callChainsMap.set(callchain.callChainId, [callchain])
            }
        })
    }

    freshCurrentCallchains(samples: FileSample[], isTopDown: boolean) {
        this.currentTreeMapData = {}
        this.currentTreeList = []
        this.allProcess = [];
        this.dataSource = []
        let totalCount = 0
        samples.forEach((sample) => {
            totalCount += sample.dur;
            let callChains = this.createThreadAndType(sample)
            let topIndex = isTopDown ? 0 : (callChains.length - 1);
            if (callChains.length > 1) {
                let root = this.currentTreeMapData[callChains[topIndex].symbolsId + "" + callChains[topIndex].pathId + sample.pid];
                if (root == undefined) {
                    root = new FileMerageBean();
                    this.currentTreeMapData[callChains[topIndex].symbolsId + "" + callChains[topIndex].pathId + sample.pid] = root;
                    this.currentTreeList.push(root)
                }
                FileMerageBean.merageCallChainSample(root, callChains[topIndex], sample, false);
                this.merageChildrenByIndex(root, callChains, topIndex, sample, isTopDown);
            }
        })
        let rootMerageMap: any = {}
        Object.values(this.currentTreeMapData).forEach((merageData: any) => {
            if (rootMerageMap[merageData.pid] == undefined) {
                let processMerageData = new FileMerageBean()//新增进程的节点数据
                processMerageData.canCharge = false
                processMerageData.symbolName = merageData.processName
                processMerageData.symbol = processMerageData.symbolName
                processMerageData.children.push(merageData)
                processMerageData.initChildren.push(merageData)
                processMerageData.dur = merageData.dur;
                processMerageData.count = merageData.count;
                processMerageData.total = totalCount;
                rootMerageMap[merageData.pid] = processMerageData
            } else {
                rootMerageMap[merageData.pid].children.push(merageData)
                rootMerageMap[merageData.pid].initChildren.push(merageData)
                rootMerageMap[merageData.pid].dur += merageData.dur;
                rootMerageMap[merageData.pid].count += merageData.count;
                rootMerageMap[merageData.pid].total = totalCount;
            }
            merageData.parentNode = rootMerageMap[merageData.pid]//子节点添加父节点的引用
        })
        let id = 0;
        this.currentTreeList.forEach((node) => {
            node.total = totalCount;
            this.setMerageName(node)
            if (node.id == "") {
                node.id = id + ""
                id++
            }
            if (node.parentNode) {
                if (node.parentNode.id == "") {
                    node.parentNode.id = id + ""
                    id++
                }
                node.parentId = node.parentNode.id
            }
        })
        this.allProcess = Object.values(rootMerageMap)
    }

    createThreadAndType(sample: FileSample){
        let typeCallchain = new FileCallChain();
        typeCallchain.callChainId = sample.callChainId
        let map:any = {}
        if(this.currentDataType == "fileSystem-queryFileSamples"){
            map = FILE_TYPE_MAP
        }else if(this.currentDataType == "fileSystem-queryIoSamples"){
            map = DISKIO_TYPE_MAP
        }else if(this.currentDataType == "fileSystem-queryVirtualMemorySamples"){
            map = VM_TYPE_MAP
        }
        // @ts-ignore
        typeCallchain.ip = map[sample.type.toString()]||"";
        typeCallchain.symbolsId = sample.type
        typeCallchain.pathId = -1;
        let threadCallChain = new FileCallChain();
        threadCallChain.callChainId = sample.callChainId
        threadCallChain.ip = (sample.threadName||"Thread")+`-${sample.tid}`
        threadCallChain.symbolsId = sample.tid;
        threadCallChain.pathId = -1;
        return [typeCallchain,threadCallChain,...(this.callChainsMap.get(sample.callChainId)||[])]
    }


    merageChildrenByIndex(currentNode: FileMerageBean, callChainDataList: any[], index: number, sample: FileSample, isTopDown: boolean) {
        isTopDown ? index++ : index--;
        let isEnd = isTopDown ? (callChainDataList.length == index + 1) : (index == 0)
        let node;
        if (currentNode.initChildren.filter((child: any) => {
            if (child.ip == callChainDataList[index]?.ip||(child.symbolsId == callChainDataList[index]?.symbolsId&&child.pathId == callChainDataList[index]?.pathId)) {
                node = child;
                FileMerageBean.merageCallChainSample(child, callChainDataList[index], sample, isEnd)
                return true;
            }
            return false;
        }).length == 0) {
            node = new FileMerageBean()
            FileMerageBean.merageCallChainSample(node, callChainDataList[index], sample, isEnd)
            currentNode.children.push(node)
            currentNode.initChildren.push(node)
            this.currentTreeList.push(node)
            node.parentNode = currentNode
        }
        if (node && !isEnd) this.merageChildrenByIndex(node, callChainDataList, index, sample, isTopDown)
    }

    setMerageName(currentNode: FileMerageBean) {
        if (currentNode.pathId == -1) {
            currentNode.canCharge = false;
            currentNode.symbol = currentNode.ip;
            currentNode.symbolName = currentNode.symbol;
            currentNode.libName = "";
            currentNode.path = "";
        } else {
            currentNode.symbol = this.data_dict.get(currentNode.symbolsId) || currentNode.ip || 'unkown'
            currentNode.path = this.data_dict.get(currentNode.pathId) || 'unkown'
            currentNode.libName = setFileName(currentNode.path)
            currentNode.symbolName = `${currentNode.symbol} (${currentNode.libName})`
        }
    }

    clearAll() {
        this.samplesData = []
        this.splitMapData = {}
        this.currentTreeMapData = {}
        this.currentTreeList = []
        this.searchValue = ""
        this.allProcess = []
        this.dataSource = []
        this.callChainsMap = new Map<number, FileCallChain[]>()
        this.splitMapData = {}
        this.searchValue = ""
        this.currentDataType = ""
    }

    clearSplitMapData(symbolName: string) {
        delete this.splitMapData[symbolName]
    }

    resolvingAction(params: any[]) {
        if (params.length > 0) {
            params.forEach((item) => {
                if (item.funcName && item.funcArgs) {
                    switch (item.funcName) {
                        case "getCallChainsBySampleIds":
                            this.freshCurrentCallchains(this.samplesData, item.funcArgs[0])
                            break
                        case "getCurrentDataFromDb":
                            this.queryCallchainsSamples(item.funcArgs[0]);
                            break
                        case "hideSystemLibrary":
                            merageBeanDataSplit.hideSystemLibrary(this.allProcess, this.splitMapData);
                            break
                        case "hideNumMaxAndMin":
                            merageBeanDataSplit.hideNumMaxAndMin(this.allProcess, this.splitMapData, item.funcArgs[0], item.funcArgs[1])
                            break
                        case "splitAllProcess":
                            merageBeanDataSplit.splitAllProcess(this.allProcess, this.splitMapData, item.funcArgs[0])
                            break
                        case "resetAllNode":
                            merageBeanDataSplit.resetAllNode(this.allProcess, this.currentTreeList, this.searchValue)
                            break
                        case "resotreAllNode":
                            merageBeanDataSplit.resotreAllNode(this.splitMapData, item.funcArgs[0])
                            break
                        case "clearSplitMapData":
                            this.clearSplitMapData(item.funcArgs[0])
                            break
                        case "splitTree":
                            merageBeanDataSplit.splitTree(this.splitMapData, this.allProcess, item.funcArgs[0], item.funcArgs[1], item.funcArgs[2], this.currentTreeList, this.searchValue);
                            break
                        case "setSearchValue":
                            this.searchValue = item.funcArgs[0]
                            break
                    }
                }
            })
            this.dataSource = this.allProcess.filter((process) => {
                return process.children && process.children.length > 0
            })
        }
        return this.dataSource
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

}

class FileCallChain {
    callChainId: number = 0;
    depth: number = 0;
    symbolsId: number = 0;
    pathId: number = 0;
    ip: string = ""
}

class FileSample {
    type:number = 0
    callChainId:number = 0;
    dur:number = 0;
    pid:number = 0;
    tid:number = 0;
    threadName:string = "";
    processName:string = ""
}

export class FileMerageBean extends MerageBean {
    ip: string = ""
    symbolsId: number = 0;
    pathId: number = 0;
    processName: string = "";
    type: number = 0

    static merageCallChainSample(currentNode: FileMerageBean, callChain: FileCallChain, sample: FileSample, isEnd: boolean) {
        if (currentNode.processName == "") {
            currentNode.ip = callChain.ip
            currentNode.pid = sample.pid
            currentNode.canCharge = true
            currentNode.pathId = callChain.pathId;
            currentNode.symbolsId = callChain.symbolsId;
            currentNode.processName = sample.processName || `Process(${sample.pid})`
        }
        if (isEnd) {
            currentNode.selfDur += sample.dur;
            currentNode.self = getProbablyTime(currentNode.selfDur)
        }
        currentNode.dur += sample.dur;
        currentNode.count++;
    }
}

export class Stack {
    type: number = 0;
    symbol: string = "";
    path: string = "";
}

export class FileSysEvent {
    isSelected:boolean = false;
    id: number = 0;
    callchainId: number = 0;
    startTs: number = 0;
    startTsStr: string = "";
    durStr: string = "";
    dur: number = 0;
    process: string = "";
    thread: string = "";
    type: number = 0;
    typeStr: string = "";
    fd: number = 0;
    size: number = 0;
    depth: number = 0;
    firstArg: string = "";
    secondArg: string = "";
    thirdArg: string = "";
    fourthArg: string = "";
    returnValue: string = "";
    error: string = "";
    path: string = "";
    symbol: string = "";
    backtrace: Array<string> = [];
}

export class IoCompletionTimes{
    isSelected:boolean = false;
    type:number = 0;
    callchainId: number = 0;
    startTs: number = 0;
    startTsStr: string = "";
    durStr: string = "";
    dur: number = 0;
    process: string = "";
    thread: string = "";
    path: string = "";
    operation: string = "";
    size: number = 0;
    sizeStr:string = "";
    blockNumber:string = "";
    tier:number = 0;
    backtrace: Array<string> = [];
    durPer4kStr: string = ""
    durPer4k: number = 0;
}

export class VirtualMemoryEvent{
    isSelected:boolean = false;
    callchainId: number = 0;
    startTs: number = 0;
    startTsStr: string = "";
    durStr: string = "";
    dur: number = 0;
    process: string = "";
    thread: string = "";
    address:string = "";
    size:number = 0;
    sizeStr:string = "";
    type:number = 0;
    tid:number = 0;
    pid:number = 0;
    operation: string = "";
}
