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
import {TabPaneThreadSwitch} from "../../../../../dist/trace/component/trace/sheet/TabPaneThreadSwitch.js"

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('TabPaneContextSwitch Test', () => {
    let tabPaneThreadSwitch = new TabPaneThreadSwitch();
    let dataArray = [{
        id: "",
        pid: "",
        title: "",
        children: [],
        process: "",
        processId: 0,
        thread: "",
        threadId: 0,
        state: "",
        wallDuration: 0,
        avgDuration: "",
        count: 0,
        minDuration: 0,
        maxDuration: 0,
        stdDuration: "",
    }]

    let val={
        leftNs:1,
        rightNs:1,
    }

    it('TabPaneThreadSwitchTest01', function () {
        let result = tabPaneThreadSwitch.groupByStateToMap(dataArray);
        expect(result.get('').length).toBe(1);
    });

    it('TabPaneThreadSwitchTest02', function () {
        let result = tabPaneThreadSwitch.groupByProcessToMap(dataArray)
        expect(result.get(0).length).toBe(1);
    });

    it('TabPaneThreadSwitchTest03', function () {
        let result = tabPaneThreadSwitch.groupByStateProcessToMap(dataArray)
        expect(result.get('').get(0).length).toBe(1);
    });


    it('TabPaneThreadSwitchTest04', function () {
        document.body.innerHTML = `<tabpane-thread-switch id="ThreadSwitch"></tabpane-thread-switch>`
        let tabPaneThreadSwitch = document.querySelector('#ThreadSwitch') as TabPaneThreadSwitch
        tabPaneThreadSwitch.data = false
        expect(tabPaneThreadSwitch.data).toBeFalsy();
    });

    it('TabPaneThreadSwitchTest06', function () {
        expect(tabPaneThreadSwitch.initElements()).toBeUndefined();
    });

    it('TabPaneThreadSwitchTest07', function () {
        expect(tabPaneThreadSwitch.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px;
        }
        </style>
        <label id=\\"time-range\\" style=\\"width: 100%;height: 20px;text-align: end;font-size: 10pt;margin-bottom: 5px\\">Selected range:0.0 ms</label>
        <lit-table id=\\"tb-ts\\" style=\\"height: auto\\" tree>
            <lit-table-column width=\\"500px\\" title=\\"Event/Process/Thread\\" data-index=\\"title\\" key=\\"title\\" align=\\"flex-start\\">
            </lit-table-column>
            <lit-table-column width=\\"1fr\\" title=\\"Count\\" data-index=\\"count\\" key=\\"count\\" align=\\"flex-start\\" >
            </lit-table-column>
        </lit-table>
        "
`);
    });
})
