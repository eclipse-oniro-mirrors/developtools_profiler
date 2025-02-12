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
import {TabPaneSdkCounter} from '../../../../../../dist/trace/component/trace/sheet/sdk/TabPaneSdkCounter.js'
// @ts-ignore
import '../../../../../../dist/trace/component/trace/sheet/sdk/TabPaneSdkCounter.js'
// @ts-ignore
import {SpSystemTrace} from "../../../../../../dist/trace/component/SpSystemTrace.js";

// @ts-ignore
import {LitTable} from "../../../../../../dist/base-ui/table/lit-table.js";

window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(() => ({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}))

const sqlite = require("../../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../../dist/trace/database/SqlLite.js");

describe('TabPaneSdkCounter Test', () => {
    document.body.innerHTML= `<lit-table id="tb-counter"></lit-table>`
    let litTable = document.querySelector("#tb-counter") as LitTable
    it('TabPaneSdkCounterTest00', () => {
        let tabPaneSdkCounter = new TabPaneSdkCounter()
        tabPaneSdkCounter.tbl = jest.fn(() => litTable)
        let a = new Map();
        let config = `{"tableConfig":{"showType":[{"tableName":"gpu_counter","inner":{"tableName":"gpu_counter_object",
        "columns":[{"column":"counter_name","type":"STRING","displayName":"","showType":[0]},{"column":"counter_id",
        "type":"INTEGER","displayName":"","showType":[0]}]},"columns":[{"column":"ts","type":"INTEGER","displayName":
        "TimeStamp","showType":[1,3]},{"column":"counter_id","type":"INTEGER","displayName":"MonitorValue","showType":
        [1,3]},{"column":"value","type":"INTEGER","displayName":"Value","showType":[1,3]}]},{"tableName":"slice_table",
        "inner":{"tableName":"slice_object_table","columns":[{"column":"slice_name","type":"STRING","displayName":"",
        "showType":[0]},{"column":"slice_id","type":"INTEGER","displayName":"","showType":[0]}]},"columns":[{"column":
        "start_ts","type":"INTEGER","displayName":"startts","showType":[2,3]},{"column":"end_ts","type":"INTEGER",
        "displayName":"endts","showType":[2,3]},{"column":"slice_id","type":"INTEGER","displayName":"slice_id",
        "showType":[2,3]},{"column":"value","type":"INTEGER","displayName":"Value","showType":[2,3]}]}]},
        "settingConfig":{"name":"mailG77","configuration":{"version":{"type":"number","default":"1","description":
        "gatord version"},"counters":{"type":"string","enum":["ARM_Mali-TTRx_JS1_ACTIVE","ARM_Mali-TTRx_JS0_ACTIVE",
        "ARM_Mali-TTRx_GPU_ACTIVE","ARM_Mali-TTRx_FRAG_ACTIVE"]},"stop_gator":{"type":"boolean","default":"true",
        "description":"stop_gator"}}}}`
        a.set("1", config)
        SpSystemTrace.SDK_CONFIG_MAP = a
        let startTime = sqlite.queryStartTime;
        let dataTime: Array<any> = [{
            start_ts: 1000
        }]
        startTime.mockResolvedValue(dataTime)

        let tabSdkCounterLeftData = sqlite.getTabSdkCounterLeftData;
        let data = [
            {
                max_value: 1000
            }, {
                max_value: 2000
            }, {
                max_value: 3000
            }
        ]
        tabSdkCounterLeftData.mockResolvedValue(data)

        let tabSdkCounterData = sqlite.getTabSdkCounterData;
        let counter = [{
            ts: 1000,
            counter_id: 0,
            value: 100
        }, {
            ts: 2000,
            counter_id: 0,
            value: 100
        }, {
            ts: 3000,
            counter_id: 0,
            value: 100
        }, {
            ts: 4000,
            counter_id: 0,
            value: 100
        }, {
            ts: 5000,
            counter_id: 0,
            value: 100
        }]
        tabSdkCounterData.mockResolvedValue(counter)

        let d = {
            cpus: [],
            threadIds: [],
            trackIds: [],
            funTids: [],
            heapIds: [],
            nativeMemory: [],
            cpuAbilityIds: [],
            memoryAbilityIds: [],
            diskAbilityIds: [],
            networkAbilityIds: [],
            leftNs: 0,
            rightNs: 0,
            hasFps: false,
            statisticsSelectData: [],
            perfSampleIds: [],
            perfCpus: [],
            perfProcess: [],
            perfThread: [],
            perfAll: false,
            sdkCounterIds: ["a-b","b-c","d-e"]
        }
        tabPaneSdkCounter.tbl.recycleDataSource = jest.fn(() => d)
        tabPaneSdkCounter.tbl.appendChild = jest.fn(() => true)
        tabPaneSdkCounter.data = d
        expect(tabPaneSdkCounter.data).toBeUndefined();
    });

    it('TabPaneSdkCounterTest01', () => {
        let tabPaneSdkCounter = new TabPaneSdkCounter()
        expect(tabPaneSdkCounter.parseJson([])).toBe("");
    });

    it('TabPaneSdkCounterTest02', () => {
        let tabPaneSdkCounter = new TabPaneSdkCounter()
        let type = {
            columns: [{showType: 'counter'}]
        }
        expect(tabPaneSdkCounter.getTableType(type)).toBe("");
    });

    it('TabPaneSdkCounterTest03', () => {
        let tabPaneSdkCounter = new TabPaneSdkCounter()
        expect(tabPaneSdkCounter.initDataElement()).toBeUndefined();
    });

    it('TabPaneSdkCounterTest05', () => {
        let tabPaneSdkCounter = new TabPaneSdkCounter()
        expect(tabPaneSdkCounter.initHtml()).toMatchInlineSnapshot(`
"
<style>
:host{
    display: flex;
    flex-direction: column;
    padding: 10px 10px;
}
</style>
<div style=\\"display: flex;height: 20px;align-items: center;flex-direction: row;margin-bottom: 5px\\">
            <stack-bar id=\\"stack-bar\\" style=\\"flex: 1\\"></stack-bar>
            <label id=\\"time-range\\"  style=\\"width: auto;text-align: end;font-size: 10pt;\\">Selected range:0.0 ms</label>
        </div>
<lit-table id=\\"tb-counter\\" style=\\"height: auto\\">
</lit-table>
        "
`);
    });

    it('TabPaneSdkCounterTest04', function () {
        let tabPaneSdkCounter = new TabPaneSdkCounter()
        tabPaneSdkCounter.tbl = jest.fn(() => true)
        tabPaneSdkCounter.tbl!.recycleDataSource = jest.fn(() => true)
        expect(tabPaneSdkCounter.sortByColumn({
            key: '',
            sort: ''
        })).toBeUndefined();
    });
})