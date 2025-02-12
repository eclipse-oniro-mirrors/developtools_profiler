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
import {TabPaneNMCallInfo} from "../../../../../dist/trace/component/trace/sheet/TabPaneNMCallInfo.js"
// @ts-ignore
import {HeapBean} from "../../../../../dist/trace/bean/HeapBean.js";
import {queryHeapAllData} from "../../../../../src/trace/database/SqlLite";
import {NativeHookCallInfo} from "../../../../../src/trace/bean/NativeHook";
const sqlit = require("../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(() => ({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}));

describe('TabPaneNMCallInfo Test', () => {
    document.body.innerHTML = '<tabpane-native-callinfo id="ddd"></tabpane-native-callinfo>'
    let tabPaneNMCallInfo = document.querySelector<TabPaneNMCallInfo>('#ddd')

    let mockGetNativeHookEventTid = sqlit.queryNativeHookEventTid

    let nativeHookData = [
        {
            eventId: 0,
            eventType: "",
            subType: "",
            heapSize: 0,
            addr: "",
            startTs: 0,
            endTs: 0,
            sumHeapSize: 0,
            max: 0,
            count: 0,
            tid: 0,
            isSelected: false,
        },
        {
            eventId: 0,
            eventType: "",
            subType: "",
            heapSize: 0,
            addr: "",
            startTs: 0,
            endTs: 0,
            sumHeapSize: 0,
            max: 0,
            count: 0,
            tid: 0,
            isSelected: false,
        },
    ]

    mockGetNativeHookEventTid.mockResolvedValue(nativeHookData);
    tabPaneNMCallInfo.currentSelection = jest.fn(()=>true)
    TabPaneNMCallInfo.data = {
        cpus:  [],
        threadIds: [],
        trackIds: [],
        funTids: [],
        heapIds: [],
        nativeMemory: [],
        leftNs:  0,
        rightNs: 0,
        hasFps: false,
        statisticsSelectData: undefined
    }
    it('TabPaneNMCallInfoTest01', function () {
        let array = new Array<HeapBean>();
        array.push({
            MoudleName: '',
            AllocationFunction: '',
            Allocations: 0,
            Deallocations: 0,
            AllocationSize: 0,
            DeAllocationSize: 0,
            Total: 0,
            RemainingSize: 0,
            children: [],
            depth: 0,
        })
        tabPaneNMCallInfo.groupByWithTid = jest.fn(()=>true)
        let handleQueryResult = tabPaneNMCallInfo.handleQueryResult(nativeHookData);
        expect(handleQueryResult).toEqual(true)
    });

    it('TabPaneNMCallInfoTest02', function () {
        tabPaneNMCallInfo.currentSelection = jest.fn(()=>true)
        tabPaneNMCallInfo.queryResult = jest.fn(()=>nativeHookData)
        expect(tabPaneNMCallInfo.filterQueryData()).toBeUndefined();
    });

    it('TabPaneNMCallInfoTest03', function () {
        let hookData = new Array<NativeHookCallInfo>();
            hookData.push({
                id: "",
                pid: "",
                library: "",
                title: "",
                count: 0,
                children: [],
                depth: 0,
                frame: undefined,
                isHover: false,
                parent: undefined,
                size: 0,
                symbol: "",
                type: 0,
                heapSize: 0,
                heapSizeStr: "",
                eventId: 0,
                threadId: 0,
                isSelected:false
            })

        tabPaneNMCallInfo.frameChart = jest.fn(()=>undefined)
        tabPaneNMCallInfo.frameChart.calculateChartData = jest.fn(()=>true)
        tabPaneNMCallInfo.frameChart.updateCanvas = jest.fn(()=>true)
        let groupByWithTid = tabPaneNMCallInfo.groupByWithTid(hookData);
        expect(groupByWithTid.length).toEqual(undefined)
    });

    it('TabPaneNMCallInfoTest04', function () {
        let hookLeft = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }

        let hookRight = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [],
            depth: 1,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }
        let ListToTree = tabPaneNMCallInfo.listToTree(hookRight, hookLeft);
        expect(ListToTree).toBeUndefined()
    });

    it('TabPaneNMCallInfoTest05', function () {
        let hookLeft = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }

        let hookRight = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [hookLeft],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }
        let groupByWithTid = tabPaneNMCallInfo.listToTree(hookLeft, hookRight);
        expect(groupByWithTid).toBeUndefined()
    });

    it('TabPaneNMCallInfoTest06', function () {
        let target = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [{length:1}],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }
        let src = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }
        let groupByWithTid = tabPaneNMCallInfo.mergeTree(target,src);
        expect(groupByWithTid).toBeUndefined()
    });

    it('TabPaneNMCallInfoTest07', function () {
        let target = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0,
            length:1
        }

        let src = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [target],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 0,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }
        let groupByWithTid = tabPaneNMCallInfo.mergeTree(target, src);
        expect(groupByWithTid).toBeUndefined()
    });

    it('TabPaneNMCallInfoTest08', function () {
        let hookLeft = {
            id: "",
            pid: '',
            library: "",
            title: "",
            count: 0,
            children: [],
            depth: 0,
            frame: undefined,
            isHover: false,
            parent: undefined,
            size: 2,
            symbol: "",
            type: 0,
            heapSize: 0,
            heapSizeStr: "",
            eventId: 0,
            threadId: 0
        }
        let groupByWithTid = tabPaneNMCallInfo.setRightTableData(hookLeft);
        expect(groupByWithTid).toBeUndefined()
    });

    it('TabPaneNMCallInfoTest10', function () {
        expect(tabPaneNMCallInfo.sortTreeByColumn()).toBeUndefined();
    });

    it('TabPaneNMCallInfoTest11', function () {
        expect(tabPaneNMCallInfo.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
        }
        tab-pane-filter {
            border: solid rgb(216,216,216) 1px;
            float: left;
            text-align: center;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        selector{
            display: none;
        }
        .show{
            margin: 0 0 60px 0;
            display: flex;
            flex: 1;
        }
        </style>
        <div style=\\"display: flex;flex-direction: row\\">
            <selector id='show_table' class=\\"show\\">
                <div style=\\"width: 65%\\">
                    <lit-table id=\\"tb-native-callinfo\\" style=\\"height: auto\\" tree>
                        <lit-table-column width=\\"70%\\" title=\\"Symbol Name\\" data-index=\\"title\\" key=\\"title\\"  align=\\"flex-start\\">
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"Size\\" data-index=\\"heapSizeStr\\" key=\\"heapSizeStr\\"  order>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"Count\\" data-index=\\"count\\" key=\\"count\\" order>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"  \\" data-index=\\"type\\" key=\\"type\\"  align=\\"flex-start\\" >
                            <template>
                                <img src=\\"img/library.png\\" size=\\"20\\" v-if=\\" type == 1 \\">
                                <img src=\\"img/function.png\\" size=\\"20\\" v-if=\\" type == 0 \\">
                                <div v-if=\\" type == - 1 \\"></div>
                            </template>
                        </lit-table-column>
                    </lit-table>
                </div>
                <div style=\\"width: 35%\\">
                    <lit-table id=\\"tb-native-data\\" no-head style=\\"height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)\\">
                        <lit-table-column width=\\"60px\\" title=\\"\\" data-index=\\"type\\" key=\\"type\\"  align=\\"flex-start\\" >
                            <template>
                                <img src=\\"img/library.png\\" size=\\"20\\" v-if=\\" type == 1 \\">
                                <img src=\\"img/function.png\\" size=\\"20\\" v-if=\\" type == 0 \\">
                            </template>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"\\" data-index=\\"title\\" key=\\"title\\"  align=\\"flex-start\\">
                        </lit-table-column>
                    </lit-table>
                </div>
            </selector>
            <selector id='show_chart'>
                <tab-framechart id='framechart' style='width: 100%;height: auto'> </tab-framechart>
            </selector>
            <tab-pane-filter id=\\"filter\\" icon first second></tab-pane-filter>
        </div>
        "
`);
    });

})
