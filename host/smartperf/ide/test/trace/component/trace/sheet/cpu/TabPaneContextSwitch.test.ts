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
import {TabPaneContextSwitch} from "../../../../../../dist/trace/component/trace/sheet/cpu/TabPaneContextSwitch.js"
window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));
describe('TabPaneContextSwitch Test', () => {
    let tabPaneContextSwitch = new TabPaneContextSwitch();
    tabPaneContextSwitch.dataArray = [{
        recordStartNs: 0,
        leftNs: 0,
        rightNs: 0,
        hasFps: false,
        statisticsSelectData: undefined,
        perfAll: false,

        cpus: [],
        cpuStateFilterIds: [],
        threadIds: [],
        processTrackIds: [],
        virtualTrackIds: [],
        funTids: [],
        funAsync: [],
        heapIds: [],
        nativeMemory: [],
        cpuAbilityIds: [],
        memoryAbilityIds: [],
        diskAbilityIds: [],
        networkAbilityIds: [],
        perfSampleIds: [],
        perfCpus: [],
        perfProcess: [],
        perfThread: [],
        fileSystemType: [],
        sdkCounterIds: [],
        sdkSliceIds: []
    }]


    it('TabPaneContextSwitchTest01', function () {
        expect(tabPaneContextSwitch).not.toBeUndefined();
    });

    it('TabPaneContextSwitchTest02', function () {
        expect(tabPaneContextSwitch.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px;
        }
        </style>
        <label id=\\"time-range\\" style=\\"width: 100%;height: 20px;text-align: end;font-size: 10pt;margin-bottom: 5px\\">Selected range:0.0 ms</label>
        <lit-table id=\\"tb-cs\\" style=\\"height: auto\\" tree>
            <lit-table-column width=\\"500px\\" title=\\"Process/Thread/Event\\" data-index=\\"title\\" key=\\"title\\" align=\\"flex-start\\">
            </lit-table-column>
            <lit-table-column width=\\"1fr\\" title=\\"Count\\" data-index=\\"count\\" key=\\"count\\" align=\\"flex-start\\" >
            </lit-table-column>
        </lit-table>
        "
`);
    });

    it('TabPaneContextSwitchTest03', function () {
        document.body.innerHTML = `<tabpane-context-switch id="Switch"></tabpane-context-switch>`
        let tabPaneContextSwitch = document.querySelector('#Switch') as TabPaneContextSwitch
        tabPaneContextSwitch.data = false
        expect(tabPaneContextSwitch.data).toBeFalsy();
    });

    it('TabPaneContextSwitchTest04', function () {
        document.body.innerHTML = `<tabpane-context-switch id="Switch"></tabpane-context-switch>`
        let tabPaneContextSwitch = document.querySelector('#Switch') as TabPaneContextSwitch
        expect(tabPaneContextSwitch.data).toBe(tabPaneContextSwitch.dataArray);
    });

    it('TabPaneContextSwitchTest05', function () {
        document.body.innerHTML = `<tabpane-context-switch id="Switch"></tabpane-context-switch>`
        let tabPaneContextSwitch = document.querySelector('#Switch') as TabPaneContextSwitch
        tabPaneContextSwitch.loadDataInCache = false;
        expect(tabPaneContextSwitch.data).toBe(tabPaneContextSwitch.dataArray);
    });
})
