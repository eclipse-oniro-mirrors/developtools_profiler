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

import {Utils} from "../component/trace/base/Utils.js";
import {ChartStruct} from "../../trace/bean/FrameChartStruct.js";
import {SpHiPerf} from "../component/chart/SpHiPerf.js";

export class PerfFile {
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

export class PerfThread {
    tid: number = 0;
    pid: number = 0;
    threadName: string = "";
    processName: string = "";
}

export class PerfCall{
    sampleId: number = 0;
    depth: number = 0;
    name: string = "";
}

export class PerfCallChain {
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

export class PerfCallChainMerageData extends ChartStruct {
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
        this.weight = `${Utils.timeMsFormat2p(this.dur * (SpHiPerf.stringResult?.fValue || 1))}`
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
            currentNode.self = Utils.timeMsFormat2p(currentNode.selfDur)
        }
        currentNode.dur++;
        currentNode.count++;
    }
}

export class PerfSample {
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

export class PerfStack {
    symbol: string = "";
    symbolId: number = 0;
    path: string = "";
    fileId: number = 0;
    type: number = 0;
    vaddrInFile: number = 0;
}

export class PerfCmdLine {
    report_value: string = "";
}