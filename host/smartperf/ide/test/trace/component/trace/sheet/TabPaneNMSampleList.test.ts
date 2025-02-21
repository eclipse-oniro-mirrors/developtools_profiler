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
import {TabPaneNMSampleList} from "../../../../../dist/trace/component/trace/sheet/TabPaneNMSampleList.js"
// @ts-ignore
import {LitTable} from "../../../../../dist/base-ui/table/lit-table";
const sqlit = require("../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(() => ({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}));
describe('TabPaneNMSampleList Test', () => {
    document.body.innerHTML = '<tabpane-native-sample id="ddt"></tabpane-native-sample>'
    let tabPaneNMSampleList = document.querySelector<TabPaneNMSampleList>('#ddt')
    let mockGeTabCounters = sqlit.getTabCounters
    let mockGetHookData = sqlit.queryAllHookData
    let mockGetNativeHookEventId = sqlit.queryNativeHookEventId
    let mockGetNativeHookSnapshot = sqlit.queryNativeHookSnapshot
    let mockGetNativeHookSnapshotTypes = sqlit.queryNativeHookSnapshotTypes

    TabPaneNMSampleList.source = [{
        current: "",
        currentSize: 0,
        startTs: 0,
        heapSize: 0,
        snapshot: "",
        growth: "",
        total: 0,
        totalGrowth: "",
        existing: 0,
        children: [],
        tempList: [],
        timestamp: "",
        eventId: -1,
    }]
    TabPaneNMSampleList.filterSelect = '0'

    tabPaneNMSampleList.currentSelection = jest.fn(()=>true)
    let dat = {
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

    let NativeHookSnapshotTypes = [{
        eventId: -1,
        current: 0,
        eventType: "",
        subType: "",
        growth: 0,
        existing: 0,
        addr: "",
        startTs: 0,
        endTs: 0,
        total: 0,
        children: [],
    }]

    mockGetNativeHookSnapshotTypes.mockResolvedValue(NativeHookSnapshotTypes);
    mockGetHookData.mockResolvedValue(NativeHookSnapshotTypes);
    mockGetNativeHookSnapshot.mockResolvedValue([]);

    tabPaneNMSampleList.data = dat
    it('TabPaneNMSampleListTest01', function () {
        expect(TabPaneNMSampleList.serSelection(dat)).toBeUndefined()
    });

    it('TabPaneNMSampleListTest02', function () {
        let sampleData = {
            index: 0,
            eventId: 0,
            eventType: "",
            subType: "",
            addr: "",
            startTs: 0,
            timestamp: "",
            heapSize: 0,
            heapSizeUnit: "",
            symbol: "",
            library: "",
        }
        expect(TabPaneNMSampleList.addSampleData(sampleData)).toBeUndefined()
    });

    it('TabPaneNMSampleListTest03', function () {
        let sampleData = {
            index: 0,
            eventId: 0,
            eventType: "",
            subType: "",
            addr: "",
            startTs: 0,
            timestamp: "",
            heapSize: 0,
            heapSizeUnit: "",
            symbol: "",
            library: "",
        }

        let snapshot = {
            current: "",
            currentSize: 0,
            startTs: 0,
            heapSize: 0,
            snapshot: "",
            growth: "",
            total: 0,
            totalGrowth: "",
            existing: 0,
            children: [],
            tempList: [],
            timestamp: "",
            eventId: -1,
        }

        expect(TabPaneNMSampleList.querySnapshot(sampleData, snapshot)).toBeUndefined()
    });

    it('TabPaneNMSampleListTest04', function () {
        let snapshot = {
            current: "",
            currentSize: 0,
            startTs: 0,
            heapSize: 0,
            snapshot: "",
            growth: "",
            total: 0,
            totalGrowth: "",
            existing: 0,
            children: [],
            tempList: [],
            timestamp: "",
            eventId: -1,
        }

        let snapshotLeft = {
            current: "",
            currentSize: 0,
            startTs: 0,
            heapSize: 0,
            snapshot: "",
            growth: "",
            total: 0,
            totalGrowth: "",
            existing: 0,
            children: [snapshot],
            tempList: [],
            timestamp: "",
            eventId: -1,
        }

        let snapshotRight = {
            current: "",
            currentSize: 0,
            startTs: 0,
            heapSize: 0,
            snapshot: "",
            growth: "",
            total: 0,
            totalGrowth: "",
            existing: 0,
            children: [snapshot],
            tempList: [],
            timestamp: "",
            eventId: -1,
        }
        expect(TabPaneNMSampleList.prepChild(snapshotLeft, snapshotRight)).toBeUndefined()
    });

    it('TabPaneNMSampleListTest05', function () {
        expect(tabPaneNMSampleList.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
        }
        </style>
        <div style=\\"display: flex;flex-direction: row\\">
        <div style=\\"width: 65%\\">
            <lit-table id=\\"tb-native-sample\\" style=\\"height: auto\\" tree>
                <lit-table-column width=\\"25%\\" title=\\"Snapshot\\" data-index=\\"snapshot\\" key=\\"snapshot\\"  align=\\"flex-start\\" >
                </lit-table-column>
                <lit-table-column width=\\"1fr\\" title=\\"Timestamp\\" data-index=\\"timestamp\\" key=\\"timestamp\\"  align=\\"flex-start\\"  >
                </lit-table-column>
                <lit-table-column width=\\"1fr\\" title=\\"Net Growth\\" data-index=\\"growth\\" key=\\"growth\\"  align=\\"flex-start\\"  >
                </lit-table-column>
                <lit-table-column width=\\"1fr\\" title=\\"Total Growth\\" data-index=\\"totalGrowth\\" key=\\"totalGrowth\\"  align=\\"flex-start\\"  >
                </lit-table-column>
                <lit-table-column width=\\"1fr\\" title=\\"# Existing\\" data-index=\\"existing\\" key=\\"existing\\"  align=\\"flex-start\\"  >
                </lit-table-column>
            </lit-table>
            <tab-pane-filter id=\\"filter\\" first></tab-pane-filter>
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
        </div>
        "
`);
    });

    it('TabPaneNMSampleListTest09', function () {
        let rootSample  ={
            growth:1,
            existing:1,
            children:[],
            total:1
        }

        let merageSample  ={
            growth:1,
            endTs:2,
            startTs:2,
            addr:"1",
            eventId:0,
        }
        expect(TabPaneNMSampleList.merageSampleData(1,1,rootSample,merageSample)).toBeUndefined()
    });
})
