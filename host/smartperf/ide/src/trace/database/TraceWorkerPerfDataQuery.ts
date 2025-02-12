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



class TraceWorkerPerfDataQuery {
    systmeRuleName = "/system/"
    numRuleName = "/max/min/"
    filesData: any = {}
    samplesData: any = {}
    threadData: any = {}
    callChainData: any = {}
    splitMapData: any = {}
    currentTreeMapData: any = {}
    currentTreeList: any[] = []
    searchValue: string = ""
    dataSource:PerfCallChainMerageData[] = []
    allProcess:PerfCallChainMerageData[] = []
    callChainMap: Map<number,PerfCall> = new Map<number, PerfCall>()

    initPerfFiles(queryFunc:Function) {
        this.clearAll()
        let files = queryFunc("queryPerfFiles", `select file_id as fileId,symbol,path from perf_files`, {})
        files.forEach((file:any) => {
            this.filesData[file.fileId] = this.filesData[file.fileId] || []
            PerfFile.setFileName(file)
            this.filesData[file.fileId].push(file)
        })
        let threads = queryFunc("queryPerfThread", `select a.thread_id as tid,a.thread_name as threadName,a.process_id as pid,b.thread_name as processName from perf_thread a left join (select * from perf_thread where thread_id = process_id) b on a.process_id = b.thread_id`, {})
        threads.forEach((thread:any) => {
            this.threadData[thread.tid] = thread
        })
        let countRes = queryFunc("queryPerfCallchainsCount",`select count(*) as count from perf_callchain where symbol_id != -1 and vaddr_in_file != 0`,{})
        if (countRes.length != 0) {
            let count: number = (countRes[0] as any).count;
            let pageSize = 500000;
            let pages = Math.ceil(count / pageSize);
            let callChains: any[] = []
            for (let i = 0; i < pages; i++) {
                let arr = queryFunc("queryPerfCallchains",`select c.name,c.sample_id as sampleId,c.callchain_id as callChainId,c.vaddr_in_file as vaddrInFile,c.file_id as fileId,c.symbol_id as symbolId,s.thread_state as threadState,s.thread_id as tid  from perf_callchain c left join perf_sample s on c.sample_id = s.sample_id
where c.symbol_id != -1 and c.vaddr_in_file != 0 limit $limit offset $offset`,
                    {$limit: pageSize, $offset:  i * pageSize})
                callChains = callChains.concat(arr)
            }
            this.initCallChainBottomUp(callChains)
        }
    }

    clearAll(){
        this.filesData = {}
        this.samplesData = {}
        this.threadData= {}
        this.callChainData = {}
        this.splitMapData = {}
        this.currentTreeMapData = {}
        this.currentTreeList = []
        this.searchValue = ""
        this.dataSource = []
        this.allProcess = []
        this.callChainMap = new Map<number, PerfCall>()
    }

    initCallChainBottomUp(callChains: PerfCallChain[]) {
        callChains.forEach((callChain, index) => {
            if (this.threadData[callChain.tid] == undefined) {
                return
            }
            this.setCallChainName(callChain);
            this.addGroupData(callChain)
            if (index + 1 < callChains.length && callChains[index + 1].sampleId == callChain.sampleId) {
                PerfCallChain.setPreviousNode(callChain, callChains[index + 1])
            }
            if (callChains.length == index + 1 || callChains[index + 1].sampleId != callChain.sampleId) {
                this.addProcessThreadStateData(callChain)
            }
        })
    }

    setCallChainName(callChain: PerfCallChain) {//设置调用栈的名称
        callChain.canCharge = true;
        callChain.pid = this.threadData[callChain.tid].pid;
        if (callChain.symbolId == -1) {
            if (this.filesData[callChain.fileId] && this.filesData[callChain.fileId].length > 0) {
                callChain.fileName = this.filesData[callChain.fileId][0].fileName
                callChain.path = this.filesData[callChain.fileId][0].path
            } else {
                callChain.fileName = "unkown"
            }
        } else {
            if (this.filesData[callChain.fileId] && this.filesData[callChain.fileId].length > callChain.symbolId) {
                callChain.fileName = this.filesData[callChain.fileId][callChain.symbolId].fileName
                callChain.path = this.filesData[callChain.fileId][callChain.symbolId].path
            } else {
                callChain.fileName = "unkown"
            }
        }
    }

    addProcessThreadStateData(callChain: PerfCallChain) {//当调用栈为调用的根节点时
        this.addPerfCallData(callChain)
        let threadCallChain = new PerfCallChain()//新增的线程数据
        threadCallChain.depth = 0
        PerfCallChain.merageCallChain(threadCallChain, callChain)
        threadCallChain.canCharge = false
        threadCallChain.name = this.threadData[callChain.tid].threadName||"Thead" + "(" + callChain.tid + ")"
        let threadStateCallChain = new PerfCallChain()//新增的线程状态数据
        PerfCallChain.merageCallChain(threadStateCallChain, callChain)
        threadStateCallChain.name = callChain.threadState || "Unkown State"
        threadStateCallChain.fileName = threadStateCallChain.name == "-" ? "Unkown Thead State" : ""
        threadStateCallChain.canCharge = false
        this.addGroupData(threadStateCallChain)
        this.addGroupData(threadCallChain)
        PerfCallChain.setNextNode(threadCallChain, threadStateCallChain)
        PerfCallChain.setNextNode(threadStateCallChain, callChain)
    }

    addPerfCallData(callChain: PerfCallChain){
        let perfCall = new PerfCall()
        perfCall.depth = this.callChainData[callChain.sampleId]?.length||0
        perfCall.sampleId = callChain.sampleId
        perfCall.name = callChain.name
        this.callChainMap.set(callChain.sampleId,perfCall)
    }

    addGroupData(callChain: PerfCallChain) {
        this.callChainData[callChain.sampleId] = this.callChainData[callChain.sampleId] || []
        this.callChainData[callChain.sampleId].push(callChain)
    }

    getCallChainsBySampleIds(sampleIds: string[], isTopDown: boolean) {
        this.allProcess = this.groupNewTreeNoId(sampleIds, isTopDown)
        return this.allProcess
    }


    groupNewTreeNoId(sampleIds: string[], isTopDown: boolean):any[] {
        this.currentTreeMapData = {}
        this.currentTreeList = []
        for (let i = 0; i < sampleIds.length; i++) {
            let callChains = this.callChainData[sampleIds[i]]
            if (callChains == undefined) continue
            let topIndex = isTopDown ? (callChains.length - 1) : 0;
            if (callChains.length > 0) {
                let root = this.currentTreeMapData[callChains[topIndex].name + callChains[topIndex].pid];
                if (root == undefined) {
                    root = new PerfCallChainMerageData();
                    this.currentTreeMapData[callChains[topIndex].name + callChains[topIndex].pid] = root;
                    this.currentTreeList.push(root)
                }
                PerfCallChainMerageData.merageCallChain(root, callChains[topIndex], isTopDown);
                this.merageChildren(root, callChains[topIndex], isTopDown);
            }
        }
        let rootMerageMap: any = {}
        Object.values(this.currentTreeMapData).forEach((merageData: any) => {
            if (rootMerageMap[merageData.pid] == undefined) {
                let processMerageData = new PerfCallChainMerageData()//新增进程的节点数据
                processMerageData.canCharge = false
                processMerageData.symbolName = this.threadData[merageData.tid].processName||`Process(${merageData.pid})`
                processMerageData.symbol = processMerageData.symbolName
                processMerageData.tid = merageData.tid
                processMerageData.children.push(merageData)
                processMerageData.initChildren.push(merageData)
                processMerageData.dur = merageData.dur;
                processMerageData.count = merageData.dur;
                processMerageData.total = sampleIds.length;
                rootMerageMap[merageData.pid] = processMerageData
            } else {
                rootMerageMap[merageData.pid].children.push(merageData)
                rootMerageMap[merageData.pid].initChildren.push(merageData)
                rootMerageMap[merageData.pid].dur += merageData.dur;
                rootMerageMap[merageData.pid].count += merageData.dur;
                rootMerageMap[merageData.pid].total = sampleIds.length;
            }
            merageData.parentNode = rootMerageMap[merageData.pid]//子节点添加父节点的引用
        })
        let id = 0;
        this.currentTreeList.forEach((node) => {
            node.total = sampleIds.length;
            if (node.id == "") {
                node.id = id + ""
                id++
            }
            if(node.parentNode){
                if (node.parentNode.id == "") {
                    node.parentNode.id = id + ""
                    id++
                }
                node.parentId = node.parentNode.id
            }
        })
        return Object.values(rootMerageMap)
    }

    merageChildren(currentNode: PerfCallChainMerageData, callChain: any, isTopDown: boolean) {
        let nextNodeKey = isTopDown ? "nextNode" : "previousNode"
        if (callChain[nextNodeKey] == undefined) return
        let node;
        if (currentNode.initChildren.filter((child: PerfCallChainMerageData) => {
            if (child.symbolName == callChain[nextNodeKey]?.name) {
                node = child;
                PerfCallChainMerageData.merageCallChain(child, callChain[nextNodeKey], isTopDown)
                return true;
            }
            return false;
        }).length == 0) {
            node = new PerfCallChainMerageData()
            PerfCallChainMerageData.merageCallChain(node, callChain[nextNodeKey], isTopDown)
            currentNode.children.push(node)
            currentNode.initChildren.push(node)
            this.currentTreeList.push(node)
            node.parentNode = currentNode
        }
        if (node) this.merageChildren(node, callChain[nextNodeKey], isTopDown)
    }

    //所有的操作都是针对整个树结构的 不区分特定的数据
    splitTree(data: PerfCallChainMerageData[], name: string, isCharge: boolean, isSymbol: boolean) {
        data.forEach((process) => {
            process.children = []
            if (isCharge) {
                this.recursionChargeInitTree(process, name, isSymbol)
            } else {
                this.recursionPruneInitTree(process, name, isSymbol)
            }
        })
        this.resetAllNode(data)
    }

    recursionChargeInitTree(node: PerfCallChainMerageData, symbolName: string, isSymbol: boolean) {
        if ((isSymbol && node.symbolName == symbolName) || (!isSymbol && node.libName == symbolName)) {
            (this.splitMapData[symbolName] = this.splitMapData[symbolName] || []).push(node)
            node.isStore++;
        }
        if (node.initChildren.length > 0) {
            node.initChildren.forEach((child) => {
                this.recursionChargeInitTree(child, symbolName, isSymbol)
            })
        }
    }

    //symbol lib charge
    recursionChargeTree(node: PerfCallChainMerageData, symbolName: string, isSymbol: boolean) {
        if ((isSymbol && node.symbolName == symbolName) || (!isSymbol && node.libName == symbolName)) {
            node.currentTreeParentNode && node.currentTreeParentNode.children.splice(node.currentTreeParentNode.children.indexOf(node), 1, ...node.children);
            node.children.forEach((child) => {
                child.currentTreeParentNode = node.currentTreeParentNode
            })
        }
        if (node.children.length > 0) {
            node.children.forEach((child) => {
                this.recursionChargeTree(child, symbolName, isSymbol)
            })
        }
    }

    recursionPruneInitTree(node: PerfCallChainMerageData, symbolName: string, isSymbol: boolean) {
        if (isSymbol && node.symbolName == symbolName || (!isSymbol && node.libName == symbolName)) {
            (this.splitMapData[symbolName] = this.splitMapData[symbolName] || []).push(node)
            node.isStore++;
            this.pruneChildren(node, symbolName)
        } else if (node.initChildren.length > 0) {
            node.initChildren.forEach((child) => {
                this.recursionPruneInitTree(child, symbolName, isSymbol)
            })
        }
    }

    //symbol lib prune
    recursionPruneTree(node: PerfCallChainMerageData, symbolName: string, isSymbol: boolean) {
        if (isSymbol && node.symbolName == symbolName || (!isSymbol && node.libName == symbolName)) {
            node.currentTreeParentNode && node.currentTreeParentNode.children.splice(node.currentTreeParentNode.children.indexOf(node), 1);
        } else {
            node.children.forEach((child) => {
                this.recursionPruneTree(child, symbolName, isSymbol)
            })
        }
    }

    recursionChargeByRule(node: PerfCallChainMerageData, ruleName: string, rule: (node: PerfCallChainMerageData) => boolean) {
        if (node.initChildren.length > 0) {
            node.initChildren.forEach((child) => {
                if (rule(child)) {
                    (this.splitMapData[ruleName] = this.splitMapData[ruleName] || []).push(child)
                    child.isStore++;
                }
                this.recursionChargeByRule(child, ruleName, rule)
            })
        }
    }

    pruneChildren(node: PerfCallChainMerageData, symbolName: string) {
        if (node.initChildren.length > 0) {
            node.initChildren.forEach((child) => {
                child.isStore++;
                (this.splitMapData[symbolName] = this.splitMapData[symbolName] || []).push(child);
                this.pruneChildren(child, symbolName)
            })
        }
    }

    hideSystemLibrary(){
        this.allProcess.forEach((item)=>{
            item.children = []
            this.recursionChargeByRule(item,this.systmeRuleName,(node)=>{
                return node.path.startsWith(this.systmeRuleName)
            })
        })
    }

    hideNumMaxAndMin(startNum:number,endNum:string){
        let max = endNum == "∞"?Number.POSITIVE_INFINITY :parseInt(endNum)
        this.allProcess.forEach((item)=>{
            item.children = []
            this.recursionChargeByRule(item,this.numRuleName,(node)=>{
                return node.dur < startNum || node.dur > max
            })
        })
    }

    clearSplitMapData(symbolName: string) {
        delete this.splitMapData[symbolName]
    }

    resotreAllNode(symbols: string[]) {
        symbols.forEach((symbol) => {
            let list = this.splitMapData[symbol];
            if (list != undefined) {
                list.forEach((item: any) => {
                    item.isStore--
                })
            }
        })
    }

    resetAllNode(data: PerfCallChainMerageData[]) {
        this.clearSearchNode()
        data.forEach((process) => {
            process.searchShow = true
        })
        this.resetNewAllNode(data)
        if (this.searchValue != "") {
            this.findSearchNode(data, this.searchValue, false)
            this.resetNewAllNode(data)
        }
    }

    resetNewAllNode(data: PerfCallChainMerageData[]) {
        data.forEach((process) => {
            process.children = []
        })
        let values = this.currentTreeList.map((item: any) => {
            item.children = []
            return item
        })
        values.forEach((item: any) => {
            if (item.parentNode != undefined) {
                if (item.isStore == 0 && item.searchShow) {
                    let parentNode = item.parentNode
                    while (parentNode != undefined && !(parentNode.isStore == 0 && parentNode.searchShow)) {
                        parentNode = parentNode.parentNode
                    }
                    if (parentNode) {
                        item.currentTreeParentNode = parentNode
                        parentNode.children.push(item)
                    }
                }
            }
        })
    }

    findSearchNode(data: PerfCallChainMerageData[], search: string, parentSearch: boolean) {
        data.forEach((node) => {
            if ((node.symbol&&node.symbol.includes(search)) || parentSearch) {
                node.searchShow = true
                let parentNode = node.currentTreeParentNode
                while (parentNode != undefined && !parentNode.searchShow) {
                    parentNode.searchShow = true
                    parentNode = parentNode.currentTreeParentNode
                }
            } else {
                node.searchShow = false
            }
            if (node.children.length > 0) {
                this.findSearchNode(node.children, search, node.searchShow)
            }
        })
    }

    clearSearchNode() {
        this.currentTreeList.forEach((node) => {
            node.searchShow = true
        })
    }

    splitAllProcess(list:any[]){
        list.forEach((item:any)=>{
            this.allProcess.forEach((process)=>{
                if(item.select == "0"){
                    this.recursionChargeInitTree(process, item.name, item.type == "symbol")
                }else {
                    this.recursionPruneInitTree(process, item.name, item.type == "symbol")
                }
            })
            if(!item.checked){
                this.resotreAllNode([item.name])
            }
        })
    }

    resolvingAction(params:any[]) {
        if (params.length > 0) {
            params.forEach((item) => {
                if (item.funcName && item.funcArgs) {
                    switch (item.funcName) {
                        case "getCallChainsBySampleIds":
                            this.allProcess = this.getCallChainsBySampleIds(item.funcArgs[0], item.funcArgs[1])
                            break
                        case "hideSystemLibrary":
                            this.hideSystemLibrary();
                            break
                        case "hideNumMaxAndMin":
                            this.hideNumMaxAndMin(item.funcArgs[0], item.funcArgs[1])
                            break
                        case "splitAllProcess":
                            this.splitAllProcess(item.funcArgs[0])
                            break
                        case "resetAllNode":

                            this.resetAllNode(this.allProcess)
                            break
                        case "resotreAllNode":
                            this.resotreAllNode(item.funcArgs[0])
                            break
                        case "clearSplitMapData":
                            this.clearSplitMapData(item.funcArgs[0])
                            break
                        case "splitTree":
                            this.splitTree(this.allProcess, item.funcArgs[0], item.funcArgs[1], item.funcArgs[2]);
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
}

let perfDataQuery = new TraceWorkerPerfDataQuery()

enum ChartMode {
    Call,
    Byte,
    Count,
}

class PerfFile {
    fileId: number = 0;
    symbol: string = ""
    path: string = ""
    fileName: string = ""

    static setFileName(data: PerfFile) {
        if (data.path) {
            let number = data.path.lastIndexOf("/");
            if (number > 0) {
                data.fileName = data.path.substring(number + 1)
                return
            }
        }
        data.fileName = data.path
    }

    setFileName() {
        if (this.path) {
            let number = this.path.lastIndexOf("/");
            if (number > 0) {
                this.fileName = this.path.substring(number + 1)
                return
            }
        }
        this.fileName = this.path
    }
}

class PerfThread {
    tid: number = 0;
    pid: number = 0;
    threadName: string = "";
    processName: string = "";
}

class PerfCallChain {
    tid: number = 0;
    pid: number = 0;
    name: string = ""
    fileName: string = "";
    threadState: string = "";
    startNS: number = 0;
    dur: number = 0;
    sampleId: number = 0;
    callChainId: number = 0;
    vaddrInFile: number = 0;
    fileId: number = 0;
    symbolId: number = 0;
    path: string = "";
    parentId: string = ""//合并之后区分的id
    id: string = ""
    topDownMerageId: string = ""//top down合并使用的id
    topDownMerageParentId: string = ""//top down合并使用的id
    bottomUpMerageId: string = ""//bottom up合并使用的id
    bottomUpMerageParentId: string = ""//bottom up合并使用的id
    depth: number = 0;
    canCharge:boolean = true
    previousNode: PerfCallChain | undefined = undefined;//将list转换为一个链表结构
    nextNode: PerfCallChain | undefined = undefined;

    static setNextNode(currentNode: PerfCallChain, nextNode: PerfCallChain) {
        currentNode.nextNode = nextNode
        nextNode.previousNode = currentNode
    }

    static setPreviousNode(currentNode: PerfCallChain, prevNode: PerfCallChain) {
        currentNode.previousNode = prevNode
        prevNode.nextNode = currentNode
    }

    static merageCallChain(currentNode: PerfCallChain, callChain: PerfCallChain) {
        currentNode.startNS = callChain.startNS
        currentNode.tid = callChain.tid
        currentNode.pid = callChain.pid
        currentNode.sampleId = callChain.sampleId
        currentNode.dur = callChain.dur
    }

}

class Rect {
    x: number = 0
    y: number = 0
    width: number = 0
    height: number = 0

    constructor(x: number, y: number, width: number, height: number) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    static contains(rect: Rect, x: number, y: number): boolean {
        return rect.x <= x && x <= rect.x + rect.width && rect.y <= y && y <= rect.y + rect.height;
    }

    static containsWithPadding(rect: Rect, x: number, y: number, paddingLeftRight: number, paddingTopBottom: number): boolean {
        return rect.x + paddingLeftRight <= x
            && x <= rect.x + rect.width - paddingLeftRight
            && rect.y + paddingTopBottom <= y
            && y <= rect.y + rect.height - paddingTopBottom;
    }

    static containsWithMargin(rect: Rect, x: number, y: number, t: number, r: number, b: number, l: number): boolean {
        return rect.x - l <= x
            && x <= rect.x + rect.width + r
            && rect.y - t <= y
            && y <= rect.y + rect.height + b;
    }

    static intersect(r1: Rect, rect: Rect): boolean {
        let maxX = r1.x + r1.width >= rect.x + rect.width ? r1.x + r1.width : rect.x + rect.width;
        let maxY = r1.y + r1.height >= rect.y + rect.height ? r1.y + r1.height : rect.y + rect.height;
        let minX = r1.x <= rect.x ? r1.x : rect.x;
        let minY = r1.y <= rect.y ? r1.y : rect.y;
        if (maxX - minX <= rect.width + r1.width && maxY - minY <= r1.height + rect.height) {
            return true;
        } else {
            return false;
        }
    }

    contains(x: number, y: number): boolean {
        return this.x <= x && x <= this.x + this.width && this.y <= y && y <= this.y + this.height;
    }

    containsWithPadding(x: number, y: number, paddingLeftRight: number, paddingTopBottom: number): boolean {
        return this.x + paddingLeftRight <= x
            && x <= this.x + this.width - paddingLeftRight
            && this.y + paddingTopBottom <= y
            && y <= this.y + this.height - paddingTopBottom;
    }

    containsWithMargin(x: number, y: number, t: number, r: number, b: number, l: number): boolean {
        return this.x - l <= x
            && x <= this.x + this.width + r
            && this.y - t <= y
            && y <= this.y + this.height + b;
    }

    /**
     * 判断是否相交
     * @param rect
     */
    intersect(rect: Rect): boolean {
        let maxX = this.x + this.width >= rect.x + rect.width ? this.x + this.width : rect.x + rect.width;
        let maxY = this.y + this.height >= rect.y + rect.height ? this.y + this.height : rect.y + rect.height;
        let minX = this.x <= rect.x ? this.x : rect.x;
        let minY = this.y <= rect.y ? this.y : rect.y;
        if (maxX - minX <= rect.width + this.width && maxY - minY <= this.height + rect.height) {
            return true;
        } else {
            return false;
        }
    }
}

class BaseStruct {
    frame: Rect | undefined
    isHover: boolean = false;
}

class ChartStruct extends BaseStruct {
    static hoverFuncStruct: ChartStruct | undefined;
    static selectFuncStruct: ChartStruct | undefined;
    static lastSelectFuncStruct: ChartStruct | undefined;
    static padding: number = 1;
    needShow = false;
    depth: number = 0;
    symbol: string = '';
    size: number = 0;
    count: number = 0;
    type: ChartMode = ChartMode.Call;
    parent: ChartStruct | undefined;
    children: Array<ChartStruct> = [];
}

class PerfCallChainMerageData extends ChartStruct {
    #parentNode: PerfCallChainMerageData | undefined = undefined
    #total = 0
    id: string = "";
    parentId: string = "";
    currentTreeParentNode: PerfCallChainMerageData | undefined = undefined;
    symbolName: string = "";
    symbol: string = ""
    libName: string = ""
    path: string = ""
    self: string = "0s"
    weight: string = ""
    weightPercent: string = ""
    selfDur: number = 0;
    dur: number = 0;
    tid: number = 0;
    pid: number = 0;
    isStore = 0;
    canCharge:boolean = true
    children: PerfCallChainMerageData[] = []
    initChildren: PerfCallChainMerageData[] = []
    type: number = 0;
    vaddrInFile: number = 0;
    isSelected: boolean = false;
    searchShow: boolean = true;

    set parentNode(data: PerfCallChainMerageData | undefined) {
        this.currentTreeParentNode = data;
        this.#parentNode = data;
    }

    get parentNode() {
        return this.#parentNode
    }

    set total(data: number) {
        this.#total = data;
        this.weight = `${timeMsFormat2p(this.dur * (1))}`
        this.weightPercent = `${(this.dur / data * 100).toFixed(1)}%`
    }

    get total() {
        return this.#total;
    }

    static merageCallChain(currentNode: PerfCallChainMerageData, callChain: PerfCallChain, isTopDown: boolean) {
        if (currentNode.symbolName == "") {
            currentNode.symbol = `${callChain.name}  ${callChain.fileName ? `(${callChain.fileName})` : ""}`
            currentNode.symbolName = callChain.name
            currentNode.pid = callChain.pid
            currentNode.tid = callChain.tid
            currentNode.libName = callChain.fileName
            currentNode.vaddrInFile = callChain.vaddrInFile;
            currentNode.canCharge = callChain.canCharge
            if (callChain.path) {
                currentNode.path = callChain.path
            }
        }
        if (callChain[isTopDown ? "nextNode" : "previousNode"] == undefined) {
            currentNode.selfDur++;
            currentNode.self = timeMsFormat2p(currentNode.selfDur)
        }
        currentNode.dur++;
        currentNode.count++;
    }
}

class PerfSample {
    sampleId: number = 0;
    time: number = 0;
    timeString: string = "";
    core: number = 0;
    coreName: string = "";
    state: string = "";
    pid: number = 0;
    processName: string = "";
    tid: number = 0;
    threadName: string = "";
    depth: number = 0;
    addr: string = "";
    fileId: number = 0;
    symbolId: number = 0;
    backtrace: Array<string> = [];
}

class PerfStack {
    symbol: string = "";
    path: string = "";
    fileId: number = 0;
    type: number = 0;
    vaddrInFile: number = 0;
}

class PerfCmdLine {
    report_value: string = "";
}

class PerfCall{
    sampleId: number = 0;
    depth: number = 0;
    name: string = "";
}

function timeMsFormat2p(ns: number) {
    let currentNs = ns
    let hour1 = 3600_000
    let minute1 = 60_000
    let second1 = 1_000; // 1 second
    let res = ""
    if (currentNs >= hour1) {
        res += Math.floor(currentNs / hour1).toFixed(2) + "h"
        return res
    }
    if (currentNs >= minute1) {
        res += Math.floor(currentNs / minute1).toFixed(2) + "min"
        return res
    }
    if (currentNs >= second1) {
        res += Math.floor(currentNs / second1).toFixed(2) + "s"
        return res
    }
    if (currentNs > 0) {
        res += currentNs.toFixed(2) + "ms";
        return res
    }
    if (res == "") {
        res = "0s";
    }
    return res
}