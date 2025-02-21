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

// @ts-ignore
import {TabPaneCurrentSelection, getTimeString} from "../../../../../dist/trace/component/trace/sheet/TabPaneCurrentSelection.js"
import {SpApplication} from "../../../../../src/trace/SpApplication";
window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
        
    }));
describe('TabPaneCurrentSelection Test', () => {
    let tabPaneCurrentSelection = new TabPaneCurrentSelection();

    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    let context = canvas.getContext("2d");

    let cpuData = [{
        cpu: 1,
        dur: 1,
        end_state: 'string',
        id: 12,
        name: 'name',
        priority: 11,
        processCmdLine: 'processCmdLine',
        processId: 111,
        processName: 'processName',
        schedId: 22,
        startTime: 0,
        tid: 100,
        type: 'type',
    }]
    let functionData = [{
        argsetid:  53161,
        depth:  0,
        dur:  570000,
        funName: "binder transaction",
        id: 92749,
        is_main_thread:  0,
        parent_id:  null,
        startTs:  9729867000,
        threadName: "Thread-15",
        tid: 2785,
    }]
    let memData = [{
        trackId: 100,
        processName:'processName',
        pid: 11,
        upid:1,
        trackName:'trackName',
        type:'type',
        track_id: 'track_id',
        value: 111,
        startTime:0,
        duration:1000,
        maxValue:4000,
        delta: 2,
    }]
    let threadData = [{
        hasSched: 14724852000,
        pid: 2519,
        processName: null,
        threadName: "ACCS0",
        tid: 2716,
        upid:  1,
        utid:  1,
        cpu: null,
        dur: 405000,
        end_ts: null,
        id: 1,
        is_main_thread: 0,
        name: "ACCS0",
        startTime: 58000,
        start_ts: null,
        state: "S",
        type: "thread",
    }]
    let wakeupBean = [{
        wakeupTime:0,
        cpu:1,
        process:'process',
        pid:11,
        thread:'thread',
        tid:22,
        schedulingLatency:33,
        schedulingDesc:'schedulingDesc',

    }]

    let queryData = [{
        id:1,
        startTime:0,
        hasSched: 14724852000,
        pid: 2519,
        processName: null,
        threadName: "ACCS0",
        tid: 2716,
        upid:  1,
        utid:  1,
        cpu: null,
        dur: 405000,
        end_ts: null,
        is_main_thread: 0,
        name: "ACCS0",
        start_ts: null,
        state: "S",
        type: "thread",

    }]
    let scrollWakeUp = [{
        startTime:0,
        pid:11,
        tid:22,

    }]
    let data = [{
        cpu: 1,
        dur: 1,
        end_state: 'string',
        id: 12,
        name: 'name',
        priority: 11,
        processCmdLine: 'processCmdLine',
        processId: 111,
        processName: 'processName',
        schedId: 22,
        startTime: 0,
        tid: 100,
        type: 'type',

    }]

    tabPaneCurrentSelection.queryWakeUpData = jest.fn(()=> 'WakeUpData')
    tabPaneCurrentSelection.queryWakeUpData.wb = jest.fn(()=>null)



    it('TabPaneCurrentSelectionTest01', function () {
        let result = tabPaneCurrentSelection.setFunctionData(functionData)
        expect(result).toBeUndefined();
    });

    it('TabPaneCurrentSelectionTest02', function () {
        let result = tabPaneCurrentSelection.setMemData(memData)
        expect(result).toBeUndefined();
    });

    it('TabPaneCurrentSelectionTest03', function () {
        let result = getTimeString(3600_000_000_002)
        expect(result).toBe('1h 2ns ');
    });

    it('TabPaneCurrentSelectionTest04', function () {
        let result = getTimeString(60000000001)
        expect(result).toBe('1m 1ns ');
    });

    it('TabPaneCurrentSelectionTest05', function () {
        let result = getTimeString(1000000001)
        expect(result).toBe('1s 1ns ');
    });

    it('TabPaneCurrentSelectionTest06', function () {
        let result = getTimeString(1000001)
        expect(result).toBe('1ms 1ns ');
    });

    it('TabPaneCurrentSelectionTest07', function () {
        let result = getTimeString(1001)
        expect(result).toBe('1μs 1ns ');
    });

    it('TabPaneCurrentSelectionTest08', function () {
        let result = getTimeString(101)
        expect(result).toBe('101ns ');
    });

    it('TabPaneCurrentSelectionTest09',function(){
        tabPaneCurrentSelection.setCpuData = jest.fn(()=>true);
        tabPaneCurrentSelection.data = jest.fn(()=>true);
        expect(tabPaneCurrentSelection.data).toBeUndefined();
    });

    it('TabPaneCurrentSelectionTest10',function(){
        expect(tabPaneCurrentSelection.setCpuData(cpuData,undefined,1)).toBeTruthy();
    });

    it('TabPaneCurrentSelectionTest13', function () {
        expect(tabPaneCurrentSelection.initCanvas()).not.toBeUndefined();
    });

    it('TabPaneCurrentSelectionTest14', function () {
        let str = {
            length:0
        }
        expect(tabPaneCurrentSelection.transferString(str)).toBe("");
    });

    it('TabPaneCurrentSelectionTest15', function () {
        expect(tabPaneCurrentSelection.transferString("&amp;")).not.toBeUndefined();
    });

    it('TabPaneCurrentSelectionTest16', function () {
        expect(tabPaneCurrentSelection.drawRight(null)).toBeUndefined();
    });

    it('TabPaneCurrentSelectionTest11',function(){
        expect(tabPaneCurrentSelection.initHtml()).toMatchInlineSnapshot(`
"
        <style>
            .current-title{
                width: 100%;
                display: flex;
                top: 0;
                background: var(--dark-background,#ffffff);
                position: sticky;
            }
            .current-title h2{
                width: 50%;
                padding: 0 10px;
                font-size: 16px;
                font-weight: 400;
                visibility: visible;
            }
            .bottom-scroll-area{
                display: flex;
                height: auto;
                overflow-y: auto;
            }
            .left-table{
                width: 50%;
                padding: 0 10px;
            }
            .right-table{
                width: 50%;
            }
        </style>
        <div style=\\"width: 100%;height: auto;position: relative\\">
            <div class=\\"current-title\\">
                <h2 id=\\"leftTitle\\"></h2>
                <h2 id=\\"rightTitle\\">Scheduling Latency</h2>
            </div>
            <div class=\\"bottom-scroll-area\\">
                <div class=\\"left-table\\">
                    <lit-table id=\\"selectionTbl\\" no-head style=\\"height: auto\\">
                        <lit-table-column title=\\"name\\" data-index=\\"name\\" key=\\"name\\" align=\\"flex-start\\"  width=\\"180px\\">
                            <template><div>{{name}}</div></template>
                        </lit-table-column>
                        <lit-table-column title=\\"value\\" data-index=\\"value\\" key=\\"value\\" align=\\"flex-start\\" >
                            <template><div style=\\"display: flex;\\">{{value}}</div></template>
                        </lit-table-column>
                    </lit-table>
                </div>
                <div class=\\"right-table\\">
                    <canvas id=\\"rightDraw\\" style=\\"width: 100%;height: 100%;\\"></canvas>
                </div>
            </div>
        </div>
        "
`);
    });
})
