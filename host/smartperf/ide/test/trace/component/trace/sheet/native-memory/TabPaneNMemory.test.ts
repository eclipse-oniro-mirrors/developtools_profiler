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
import {TabPaneNMemory} from "../../../../../../dist/trace/component/trace/sheet/native-memory/TabPaneNMemory.js"
// @ts-ignore
import {TabPaneNMSampleList} from "../../../../../../dist/trace/component/trace/sheet/native-memory/TabPaneNMSampleList.js";

const sqlit = require("../../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(() => ({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}));

describe('TabPaneNMemory Test', () => {
    let tabPaneNMemory = new TabPaneNMemory();
    let val = {
        statisticsSelectData: {
            memoryTap: 1
        }
    }
    let hook = {eventId: 1}


    it('TabPaneNMemoryTest01', function () {
        expect(tabPaneNMemory.initFilterTypes()).toBeUndefined();
    });

    it('TabPaneNMemoryTest02', function () {
        let MockqueryNativeHookEventTid = sqlit.queryNativeHookEventTid;
        MockqueryNativeHookEventTid.mockResolvedValue([{
            eventId: 0,
            eventType: "MmapEvent",
            heap_size: 2,
            addr: "addr",
            startTs: 0,
            endTs: 500,
            tid: 2,
            threadName: "threadName"
        }])

        let MockNativeHookSnapshotTypes = sqlit.queryNativeHookSnapshotTypes;
        MockNativeHookSnapshotTypes.mockResolvedValue([{
            eventType: "MmapEvent",
            subType: ""
        }])

        let tab = new TabPaneNMSampleList()
        tabPaneNMemory.startWorker = jest.fn(() => true)
        tabPaneNMemory.data = {
            leftNs: 0,
            rightNs: 500,
            nativeMemory: "All Anonymous VM"
        }
        expect(tabPaneNMemory.initFilterTypes()).toBeUndefined();
    });

    it('TabPaneNMemoryTest08', function () {
        expect(tabPaneNMemory.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
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
        .progress{
            bottom: 33px;
            position: absolute;
            height: 1px;
            left: 0;
            right: 0;
        }
        tab-pane-filter {
            border: solid rgb(216,216,216) 1px;
            float: left;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        </style>
        <div style=\\"display: flex;flex-direction: column\\">
            <div style=\\"display: flex;flex-direction: row\\">
                <lit-slicer style=\\"width:100%\\">
                    <div style=\\"width: 65%\\">
                        <lit-table id=\\"tb-native-memory\\" style=\\"height: auto\\">
                            <lit-table-column width=\\"60px\\" title=\\"#\\" data-index=\\"index\\" key=\\"index\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                            <lit-table-column width=\\"1fr\\" title=\\"Address\\" data-index=\\"addr\\" key=\\"addr\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                            <lit-table-column width=\\"1fr\\" title=\\"Memory Type\\" data-index=\\"eventType\\" key=\\"eventType\\"  align=\\"flex-start\\">
                            </lit-table-column>
                            <lit-table-column width=\\"1fr\\" title=\\"Timestamp\\" data-index=\\"timestamp\\" key=\\"timestamp\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                            <lit-table-column width=\\"1fr\\" title=\\"State\\" data-index=\\"state\\" key=\\"state\\"  align=\\"flex-start\\">
                            </lit-table-column>
                            <lit-table-column width=\\"1fr\\" title=\\"Size\\" data-index=\\"heapSizeUnit\\" key=\\"heapSizeUnit\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                            <lit-table-column width=\\"20%\\" title=\\"Responsible Library\\" data-index=\\"library\\" key=\\"library\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                            <lit-table-column width=\\"20%\\" title=\\"Responsible Caller\\" data-index=\\"symbol\\" key=\\"symbol\\"  align=\\"flex-start\\" order>
                            </lit-table-column>
                        </lit-table>
                    </div>
                    <lit-slicer-track ></lit-slicer-track>
                    <lit-table id=\\"tb-native-data\\" no-head style=\\"height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)\\">
                        <lit-table-column width=\\"80px\\" title=\\"\\" data-index=\\"type\\" key=\\"type\\"  align=\\"flex-start\\" >
                            <template>
                                <div v-if=\\" type == -1 \\">Thread:</div>
                                <img src=\\"img/library.png\\" size=\\"20\\" v-if=\\" type == 1 \\">
                                <img src=\\"img/function.png\\" size=\\"20\\" v-if=\\" type == 0 \\">
                            </template>
                        </lit-table-column>
                        <lit-table-column width=\\"1fr\\" title=\\"\\" data-index=\\"title\\" key=\\"title\\"  align=\\"flex-start\\">
                        </lit-table-column>
                    </lit-table>
                </lit-slicer>
            </div>
            <lit-progress-bar class=\\"progress\\"></lit-progress-bar>
            <tab-pane-filter id=\\"filter\\" mark first second></tab-pane-filter>
            <div class=\\"loading\\"></div>
        </div>
        "
`);
    });

    it('TabPaneNMemoryTest09', function () {
        tabPaneNMemory.tblData = jest.fn(() => undefined)
        tabPaneNMemory.tblData.recycleDataSource = jest.fn(() => true)
        tabPaneNMemory.startWorker = jest.fn(() => true)
        expect(tabPaneNMemory.setRightTableData(hook)).toBeUndefined();
    });
    it('TabPaneNMemoryTest010', function () {
        let column = "index";
        let sort = 0;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
    it('TabPaneNMemoryTest011', function () {
        let column = "index";
        let sort = 1;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
    it('TabPaneNMemoryTest012', function () {
        let column = "addr"
        let sort = 1;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
    it('TabPaneNMemoryTest013', function () {
        let column = "timestamp"
        let sort = 1;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
    it('TabPaneNMemoryTest014', function () {
        let column = "heapSizeUnit"
        let sort = 1;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
    it('TabPaneNMemoryTest015', function () {
        let column = "library"
        let sort = 1;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
    it('TabPaneNMemoryTest016', function () {
        let column = "symbol"
        let sort = 1;
        expect(tabPaneNMemory.sortByColumn(column, sort)).toBeUndefined();
    });
})