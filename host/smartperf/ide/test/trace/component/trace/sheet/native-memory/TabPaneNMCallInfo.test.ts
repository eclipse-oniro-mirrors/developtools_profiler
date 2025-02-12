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
import {TabPaneNMCallInfo} from "../../../../../../dist/trace/component/trace/sheet/native-memory/TabPaneNMCallInfo.js"
const sqlit = require("../../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(() => ({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}));

describe('TabPaneNMCallInfo Test', () => {
    document.body.innerHTML = '<tabpane-native-callinfo id="ddd"></tabpane-native-callinfo>'
    let tabPaneNMCallInfo = document.querySelector<TabPaneNMCallInfo>('#ddd')

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
        let tab = new TabPaneNMCallInfo()
        let MockqueryNativeHookEventTid = sqlit.queryNativeHookEventTid;
        MockqueryNativeHookEventTid.mockResolvedValue([{
            eventId: 0,
            eventType: "AllocEvent",
            heap_size: 2,
            addr: "addr",
            startTs: 0,
            endTs: 500,
            tid: 2,
            threadName: "threadName"
        }])
        tab.data = {
            leftNs: 0,
            rightNs: 500,
            nativeMemory: "All Heap & Anonymous VM"
        }

        tab.startWorker = jest.fn(()=>true)
        expect(tab.data).toBeUndefined();
    });

    it('TabPaneNMCallInfoTest12', function () {
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
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        selector{
            display: none;
        }
        .progress{
            bottom: 33px;
            position: absolute;
            height: 1px;
            left: 0;
            right: 0;
        } 
        .loading{
            bottom: 0;
            position: absolute;
            left: 0;
            right: 0;
            width:100%;
            background:transparent;
            z-index: 999999;
        }
        .show{
            display: flex;
            flex: 1;
        }
        </style>
        <div style=\\"display: flex;flex-direction: row\\">
            <selector id='show_table' class=\\"show\\">
            <lit-slicer style=\\"width:100%\\">
                <div style=\\"width: 65%\\">
                    <lit-table id=\\"tb-native-callinfo\\" style=\\"height: auto\\" tree>
                        <lit-table-column width=\\"60%\\" title=\\"Symbol Name\\" data-index=\\"title\\" key=\\"title\\"  align=\\"flex-start\\">
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"Size\\" data-index=\\"heapSizeStr\\" key=\\"heapSizeStr\\"  align=\\"flex-start\\" order>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"%\\" data-index=\\"heapPercent\\" key=\\"heapPercent\\" align=\\"flex-start\\"  order>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"Count\\" data-index=\\"countValue\\" key=\\"countValue\\" align=\\"flex-start\\" order>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"%\\" data-index=\\"countPercent\\" key=\\"countPercent\\" align=\\"flex-start\\" order>
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
                <lit-slicer-track ></lit-slicer-track>
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
                </lit-slicer>
            </selector>
            <selector id='show_chart'>
                <tab-framechart id='framechart' style='width: 100%;height: auto'> </tab-framechart>
            </selector>
            <lit-progress-bar class=\\"progress\\"></lit-progress-bar>
            <tab-pane-filter id=\\"filter\\" icon first second></tab-pane-filter>
            <div class=\\"loading\\"></div>
        </div>
        "
`);
    });
    it('TabPaneNMCallInfoTest04', function () {
        TabPaneNMCallInfo.getParentTree = jest.fn(()=>true)
        let hook = {
            id:"1",
            dur:1,
            children:[],
        }
        let id = "1";
        expect(tabPaneNMCallInfo.getParentTree([hook],{id},[])).not.toBeUndefined();
    });
    it('TabPaneNMCallInfoTest05', function () {
        TabPaneNMCallInfo.getChildTree = jest.fn(()=>true)
        let hook = {
            eventId:"1",
            dur:1,
            children:[],
        }
        expect(tabPaneNMCallInfo.getChildTree([hook],"1",[])).not.toBeUndefined();
    });
    it('TabPaneNMCallInfoTest13', function () {
        expect(tabPaneNMCallInfo.showButtomMenu()).toBeUndefined();
    });
    it('TabPaneNMCallInfoTest14', function () {
        let isShow = 1;
        expect(tabPaneNMCallInfo.showButtomMenu(isShow)).toBeUndefined();
    });
})
