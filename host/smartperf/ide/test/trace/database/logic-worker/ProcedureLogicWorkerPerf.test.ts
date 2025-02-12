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
import {ProcedureLogicWorkerPerf, PerfCountSample,PerfCallChainMerageData, PerfStack, PerfCmdLine, PerfCall,timeMsFormat2p,PerfFile,PerfThread,PerfCallChain} from "../../../../dist/trace/database/logic-worker/ProcedureLogicWorkerPerf.js"

describe('ProcedureLogicWorkerPerf Test', ()=> {

    it('ProcedureLogicWorkerPerfTest', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        expect(procedureLogicWorkerPerf).not.toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest01', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-init'
        }
        procedureLogicWorkerPerf.initPerfFiles = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest02', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-queryPerfFiles'
        }
        procedureLogicWorkerPerf.initPerfThreads = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest03', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-queryPerfThread'
        }
        procedureLogicWorkerPerf.initPerfCalls = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest04', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-queryPerfCalls'
        }
        procedureLogicWorkerPerf.initPerfCallchains = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest05', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-queryPerfCallchains'
        }
        window.postMessage = jest.fn(()=>true)
        procedureLogicWorkerPerf.initCallChainTopDown = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest06', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-queryCallchainsGroupSample'
        }
        window.postMessage = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest07', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let data = {
            id:1,
            params:[{
                list:'',
            }],
            action:'',
            type: 'perf-action'
        }
        procedureLogicWorkerPerf.resolvingAction = jest.fn(()=>true)
        window.postMessage = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.handle(data)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest08', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        expect(procedureLogicWorkerPerf.clearAll()).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest09', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let callChain = [{
            sampleId: '',
            depth: 0,
            canCharge: false,
            name: '',
            tid: '',
            fileName: '',
            threadName: '',
        }]
        expect(procedureLogicWorkerPerf.initCallChainBottomUp(callChain)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest10', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let callChain = [{
            sampleId: '',
            depth: 0,
            canCharge: false,
            name: '',
            tid: '',
            fileName: '',
            threadName: '',
        }]
        expect(procedureLogicWorkerPerf.initCallChainTopDown([callChain])).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest11', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let callChain = {
            sampleId: -1,
            depth: 0,
            canCharge: true,
            name: '',
            tid: '',
            fileName: '',
            threadName: '',
            symbolId:-1
        }
        expect(procedureLogicWorkerPerf.setCallChainName(callChain)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest12', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let callChain = {
            sampleId: 0,
        }
        expect(procedureLogicWorkerPerf.setCallChainName(callChain)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest14', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let callChain = {
            sampleId: '',
            depth: 0,
            canCharge: false,
            name: '',
            tid: '',
            fileName: '',
            threadName: '',
        }
        expect(procedureLogicWorkerPerf.addPerfCallData(callChain)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest15', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let callChain = {
            sampleId: '',
        }
        expect(procedureLogicWorkerPerf.addGroupData(callChain)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest16', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        expect(procedureLogicWorkerPerf.getCallChainsBySampleIds([],[])).toBeTruthy();
    });

    it('ProcedureLogicWorkerPerfTest17', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        expect(procedureLogicWorkerPerf.freshCurrentCallchains([],1)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest19', function () {
        let perfCountSample = new PerfCountSample();
        perfCountSample = {
            sampleId: 0,
            count: 0,
            pid: 0,
            tid: 0,
            threadState: '',
        }
        expect(perfCountSample).not.toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest20', function () {
        let perfStack = new PerfStack();
        perfStack = {
            sample: '',
            path: '',
            fileId: 0,
            type: 0,
            vaddrInFile: 0,
        }
        expect(perfStack).not.toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest21', function () {
        let perfCmdLine = new PerfCmdLine();
        perfCmdLine = {
            report_value: '',
        }
        expect(perfCmdLine).not.toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest21', function () {
        let perfCmdLine = new PerfCmdLine();
        perfCmdLine = {
            report_value: '',
        }
        expect(perfCmdLine).not.toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest21', function () {
        let perfCall = new PerfCall();
        perfCall = {
            sampleId: 0,
            name: '',
            depth: 0,
        }
        expect(perfCall).not.toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest22', function () {
        expect(timeMsFormat2p('')).toBe("0s");
    });

    it('ProcedureLogicWorkerPerfTest23', function () {
        expect(timeMsFormat2p(3600_000)).toBe("1.00h");
    });

    it('ProcedureLogicWorkerPerfTest24', function () {
        expect(timeMsFormat2p(60_000)).toBe("1.00min");
    });

    it('ProcedureLogicWorkerPerfTest25', function () {
        expect(timeMsFormat2p(1_000)).toBe("1.00s");
    });

    it('ProcedureLogicWorkerPerfTest26', function () {
        expect(timeMsFormat2p(100)).toBe("100.00ms");
    });

    it('ProcedureLogicWorkerPerfTest31', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.recursionChargeInitTree = jest.fn(()=>undefined);
        let node = [{
            symbolName: '',
            libName: '',
            length: 1,
            initChildren: {
                length: 1,
            }
        }]
        expect(procedureLogicWorkerPerf.recursionChargeInitTree(node,'',true)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest32', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        expect(procedureLogicWorkerPerf.splitTree([],'','',true)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest33', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.recursionPruneInitTree = jest.fn(()=>undefined);
        let node = {
            symbolName: '',
            libName: '',
            length: 1,
            initChildren: {
                length: 1,
            }
        }
        expect(procedureLogicWorkerPerf.recursionPruneInitTree(node,'',true)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest34', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.recursionChargeByRule = jest.fn(()=>undefined);
        let node = {
            initChildren: [{
                length: 1,
            }]
        }
        let rule = {
            child: {
                isStore: 1,
            }
        }
        expect(procedureLogicWorkerPerf.recursionChargeByRule(node,'',rule)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest35', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        window.postMessage = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.queryData("","","")).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest36', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.queryData = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.initPerfFiles()).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest37', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.queryData = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.initPerfThreads()).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest38', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.queryData = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.initPerfCalls()).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest39', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.queryData = jest.fn(()=>true)
        expect(procedureLogicWorkerPerf.initPerfCallchains()).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest40', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        procedureLogicWorkerPerf.queryData = jest.fn(()=>true)
        let selectionParam = {
            perfAll:'',
            perfCpus:[1],
            perfProcess:[2],
            perfThread:[1],
            leftNs:0,
            rightNs:0
        }
        expect(procedureLogicWorkerPerf.getCurrentDataFromDb(selectionParam)).toBeUndefined();
    });

    it('ProcedureLogicWorkerPerfTest41', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let currentNode = {
            children:[],
            initChildren:[],
        }
        let list = [{
            length:1,
            name:""
        }]
        expect(procedureLogicWorkerPerf.merageChildren(currentNode,list,true)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest42', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let sampleIds = {
            length:1,
        }
        let isTopDown = {

        }
        expect(procedureLogicWorkerPerf.groupNewTreeNoId(sampleIds, isTopDown)).toStrictEqual([]);
    });
    it('ProcedureLogicWorkerPerfTest43', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let node = {
            initChildren:{
                length:1,
                forEach:jest.fn(()=>true)
            },
            libName:1
        }
        let symbolName = 1;

        let isSymbol = true;
        expect(procedureLogicWorkerPerf.recursionChargeInitTree(node, symbolName, isSymbol)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest44', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let node = {
            children:{
                length:1,
                forEach:jest.fn(()=>true)
            },
            libName:1
        }
        let symbolName = 1;

        let isSymbol = true;
        expect(procedureLogicWorkerPerf.recursionChargeTree(node, symbolName, isSymbol)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest45', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let node = {
            initChildren:{
                length:1,
                forEach:jest.fn(()=>true)
            },
            libName:1
        }
        let symbolName = 1;

        let isSymbol = true;
        expect(procedureLogicWorkerPerf.recursionPruneInitTree(node, symbolName, isSymbol)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest46', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let node = {
            children:{
                length:1,
                forEach:jest.fn(()=>true)
            },
            libName:1
        }
        let symbolName = 1;

        let isSymbol = true;
        expect(procedureLogicWorkerPerf.recursionPruneTree(node, symbolName, isSymbol)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest47', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let node = {
            initChildren:{
                length:1,
                forEach:jest.fn(()=>true)
            },
        }
        let ruleName = 1;

        let rule = true;
        expect(procedureLogicWorkerPerf.recursionChargeByRule(node, ruleName, rule)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest48', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        let node = {
            initChildren:{
                length:1,
                forEach:jest.fn(()=>true)
            },
        }
        let symbolName = 1;
        expect(procedureLogicWorkerPerf.pruneChildren(node, symbolName)).toBeUndefined();
    });
    it('ProcedureLogicWorkerPerfTest49', function () {
        let procedureLogicWorkerPerf = new ProcedureLogicWorkerPerf();
        expect(procedureLogicWorkerPerf.clearSplitMapData()).toBeUndefined();
    });
    it('PerfFileTest01', function () {
        let perfFile = new PerfFile();
        expect(perfFile.constructor()).toBeUndefined();
    });
    it('PerfFileTest02', function () {
        let perfFile = new PerfFile();
        let path=true
        expect(perfFile.setFileName(path)).toBeUndefined();
    });
    it('PerfThreadTest01', function () {
        let perfThread = new PerfThread();
        expect(perfThread.constructor()).toBeUndefined();
    });
    it('PerfCallChainTest01', function () {
        let perfCallChain = new PerfCallChain();
        expect(perfCallChain.constructor()).toBeUndefined();
    });
    it('PerfCallChainMerageDataTest01', function () {
        let perfCallChainMerageData = new PerfCallChainMerageData();
        expect(perfCallChainMerageData.constructor()).toEqual({"canCharge": true, "children": [], "count": 0, "currentTreeParentNode": undefined,
            "depth": 0, "dur": 0, "id": "", "initChildren": [], "isSelected": false, "isStore": 0, "libName": "",
            "parentId": "", "path": "", "pid": 0, "searchShow": true, "self": "0s", "selfDur": 0, "size": 0, "symbol": "",
            "symbolName": "", "tid": 0, "type": 0, "vaddrInFile": 0, "weight": "", "weightPercent": ""});
    });
    it('PerfCallChainMerageDataTest03', function () {
        let perfCallChainMerageData = new PerfCallChainMerageData();
        perfCallChainMerageData.parentNode = true
        expect(perfCallChainMerageData.parentNode).toBeTruthy()
    });
    it('PerfCallChainMerageDataTest04', function () {
        let perfCallChainMerageData = new PerfCallChainMerageData();
        perfCallChainMerageData.total = true
        expect(perfCallChainMerageData.total).toBeTruthy()
    });
})