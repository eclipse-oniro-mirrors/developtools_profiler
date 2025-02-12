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

//@ts-ignore
import {perfDataQuery} from "../../../../dist/trace/component/chart/PerfDataQuery.js"

describe('perfDataQuery Test',()=>{

    it('perfDataQueryTest01 ', function () {
        let callChain  = {
            symbolId:-1,
            fileId:1,
            fileName:"unkown",
            vaddrInFile:1,
            pid:1,
            tid:1,
            canCharge:true,
            path:'',
        }
        expect(perfDataQuery.setCallChainName(callChain)).toBe("+0x1");
    });

    it('perfDataQueryTest15 ', function () {
        let callChain  = {
            symbolId:0,
            fileId:1,
            fileName:"unkown",
            vaddrInFile:1,
        }
        expect(perfDataQuery.setCallChainName(callChain)).toBe("+0x1");
    });

    it('perfDataQueryTest02 ', function () {
        let callChain  = {
            tid:1,
            threadState:"",
            bottomUpMerageId:"1",
        }
        perfDataQuery.threadData[callChain.tid] = jest.fn(()=>[])
        perfDataQuery.threadData[callChain.tid].threadName = jest.fn(()=>"")
        expect(perfDataQuery.addProcessThreadStateData(callChain)).toBeUndefined();
    });

    it('perfDataQueryTest03 ', function () {
        perfDataQuery.groupNewTreeNoId = jest.fn(()=>true)
        expect(perfDataQuery.getCallChainsBySampleIds([{length:1}],true)).not.toBeUndefined();
    });

    it('perfDataQueryTest06 ', function () {
        let callChain  = [{name:""}]
        let currentNode  = {
            initChildren:[],
            id:"",
            children:[],
        }
        expect(perfDataQuery.merageChildren(currentNode,callChain,true)).toBeUndefined();
    });

    it('perfDataQueryTest07 ', function () {
        perfDataQuery.perfDataQuery = jest.fn(()=>true)
        expect(perfDataQuery.splitTree([],"",true,true)).toBeUndefined();
    });

    it('perfDataQueryTest08 ', function () {
        expect(perfDataQuery.clearSplitMapData("name")).toBeUndefined();
    });

    it('perfDataQueryTest09 ', function () {
        expect(perfDataQuery.resetAllNode([])).toBeUndefined();
    });

    it('perfDataQueryTest11 ', function () {
        expect(perfDataQuery.findSearchNode([],'')).toBeUndefined();
    });

    it('perfDataQueryTest14 ', function () {
        expect(perfDataQuery.initCallChainBottomUp([])).toBeUndefined();
    });

    it('perfDataQueryTest17 ', function () {
        let callChainsData  = [{
            tid: 0,
            pid: 0,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 0,
            dur: 0,
            sampleId: 0,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: 0,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        },{
            tid: 1,
            pid: 1,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 1,
            dur: 1,
            sampleId: 1,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: 0,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        }]
        expect(perfDataQuery.initCallChainBottomUp(callChainsData)).toBeUndefined();
    });

    it('perfDataQueryTest18 ', function () {
        let callChainsData  = [{
            tid: 100,
            pid: 100,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 0,
            dur: 0,
            sampleId: 0,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: 0,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        },{
            tid: 111,
            pid: 111,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 11,
            dur: 11,
            sampleId: 11,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: 0,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        },{
            tid: 222,
            pid: 222,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 22,
            dur: 22,
            sampleId: 22,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: 0,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        }]
        expect(perfDataQuery.initCallChainBottomUp(callChainsData)).toBeUndefined();
    });

    it('perfDataQueryTest19 ', function () {
        let callChainsData  = [{
            tid: 100,
            pid: 100,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 0,
            dur: 0,
            sampleId: 0,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: -1,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        }]
        expect(perfDataQuery.setCallChainName(callChainsData)).not.toBeUndefined();
    });

    it('perfDataQueryTest21 ', function () {
        perfDataQuery.groupNewTreeNoId = jest.fn(()=>true);
        let sampleIds  = [{
            tid: 10,
            pid: 100,
            length: 0,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 0,
            dur: 0,
            sampleId: 0,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: -1,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        }]
        expect(perfDataQuery.getCallChainsBySampleIds(sampleIds, true)).not.toBeUndefined();
    });

    it('perfDataQueryTest12 ', function () {
        let callChainsData  = [{
            tid: 100,
            pid: 100,
            name: "",
            fileName: "",
            threadState: "",
            startNS: 0,
            dur: 0,
            sampleId: 0,
            callChainId: 0,
            vaddrInFile: 0,
            fileId: 0,
            symbolId: -1,
            path: "",
            parentId: "",
            id: "",
            topDownMerageId: "",
            topDownMerageParentId: "",
            bottomUpMerageId: "",
            bottomUpMerageParentId: "",
            depth: 0,
            previousNode: undefined,
            nextNode: undefined,
        }]

        let currentData = {
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.merageChildren(currentData, callChainsData,true)).toBeUndefined();
    });
    it('perfDataQueryTest14 ', function () {
        let node ={
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.recursionChargeInitTree(node,'',true)).toBeUndefined();

    });

    it('perfDataQueryTest15 ', function () {
        let node ={
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.recursionChargeTree(node,'',true)).toBeUndefined();

    });

    it('perfDataQueryTest16 ', function () {
        let node ={
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.recursionPruneInitTree(node,'',true)).toBeUndefined();

    });

    it('perfDataQueryTest17 ', function () {
        let node ={
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.recursionPruneTree(node,'',true)).toBeUndefined();

    });

    it('perfDataQueryTest18 ', function () {
        let node ={
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.recursionChargeByRule(node,'',true)).toBeUndefined();

    });

    it('perfDataQueryTest19 ', function () {
        let node ={
            id: "",
            parentId: "",
            currentTreeParentNode: undefined,
            symbolName: "",
            symbol: "",
            libName: "",
            path: "",
            self: "0s",
            weight: "",
            selfDur: 0,
            dur: 0,
            tid: 0,
            pid: 0,
            isStore: 0,
            children: [],
            initChildren: [],
            type: 0,
            vaddrInFile: 0,
            isSelected: false,
            searchShow: true,
        }
        expect(perfDataQuery.pruneChildren(node,'')).toBeUndefined();

    });

    it('perfDataQueryTest20 ', function () {

        expect(perfDataQuery.clearSplitMapData('')).toBeUndefined();

    });
    it('perfDataQueryTest21 ', function () {
        expect(perfDataQuery.clearSearchNode()).toBeUndefined();
    });

})