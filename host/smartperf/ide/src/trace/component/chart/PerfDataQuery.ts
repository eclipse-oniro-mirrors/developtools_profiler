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
    queryPerfFiles,
    query, threadPool,
} from "../../database/SqlLite.js";
import {PerfCall, PerfCallChain, PerfCallChainMerageData, PerfFile} from "../../bean/PerfProfile.js";
import {info} from "../../../log/Log.js";
import {SpHiPerf} from "./SpHiPerf.js";
import {procedurePool} from "../../database/Procedure.js";

export class PerfDataQuery {

    filesData: any = {}
    samplesData: any = {}
    threadData: any = {}
    callChainData: any = {}
    splitMapData: any = {}
    currentTreeMapData: any = {}
    currentTreeList: any[] = []
    searchValue: string = ""
    callChainMap: Map<number,PerfCall> = new Map<number, PerfCall>()

    async initPerfCache(){
        await this.initPerfCallChainMap()
        await this.initPerfFiles();
    }

    async initPerfCallChainMap(){
        this.callChainMap.clear();
    }

    async initPerfFiles() {
        let files = await queryPerfFiles()
        info("PerfFiles Data size is: ", files!.length)
        files.forEach((file) => {
            this.filesData[file.fileId] = this.filesData[file.fileId] || []
            PerfFile.setFileName(file)
            this.filesData[file.fileId].push(file)
        })
        let results = await new Promise<any>((resolve, reject) => {
            procedurePool.submitWithName("logic0","perf-init",SpHiPerf.stringResult,undefined,(res:any)=>{
                resolve(res)
            })
        })
        this.callChainMap = (results as any)
        info("Perf Files Data initialized")
    }

    initCallChainBottomUp(callChains: PerfCallChain[]) {
        callChains.forEach((callChain, index) => {
            if (this.threadData[callChain.tid] == undefined) {
                return
            }
            callChain.name = this.setCallChainName(callChain)
            this.addGroupData(callChain)
            if (index + 1 < callChains.length && callChains[index + 1].sampleId == callChain.sampleId) {
                PerfCallChain.setPreviousNode(callChain, callChains[index + 1])
            }
            if (callChains.length == index + 1 || callChains[index + 1].sampleId != callChain.sampleId) {
                this.addProcessThreadStateData(callChain)
            }
        })
    }

    setCallChainName(callChain: PerfCallChain): string {//设置调用栈的名称
        callChain.pid = this.threadData[callChain.tid]?.pid;
        callChain.canCharge = true;
        if (callChain.symbolId == -1) {
            if (this.filesData[callChain.fileId] && this.filesData[callChain.fileId].length > 0) {
                callChain.fileName = this.filesData[callChain.fileId][0].fileName
                callChain.path = this.filesData[callChain.fileId][0].path
                return this.filesData[callChain.fileId][0].fileName + "+0x" + callChain.vaddrInFile
            } else {
                callChain.fileName = "unkown"
                return "+0x" + callChain.vaddrInFile
            }
        } else {
            if (this.filesData[callChain.fileId] && this.filesData[callChain.fileId].length > callChain.symbolId) {
                callChain.fileName = this.filesData[callChain.fileId][callChain.symbolId].fileName
                callChain.path = this.filesData[callChain.fileId][callChain.symbolId].path
                return this.filesData[callChain.fileId][callChain.symbolId].symbol
            } else {
                callChain.fileName = "unkown"
                return "+0x" + callChain.vaddrInFile
            }
        }
    }

    addProcessThreadStateData(callChain: PerfCallChain) {//当调用栈为调用的根节点时
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

    addGroupData(callChain: PerfCallChain) {
        this.callChainData[callChain.sampleId] = this.callChainData[callChain.sampleId] || []
        this.callChainData[callChain.sampleId].push(callChain)
    }

    getCallChainsBySampleIds(sampleIds: string[], isTopDown: boolean) {
        return this.groupNewTreeNoId(sampleIds, isTopDown)
    }


    groupNewTreeNoId(sampleIds: string[], isTopDown: boolean) {
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
}

export const perfDataQuery = new PerfDataQuery()
