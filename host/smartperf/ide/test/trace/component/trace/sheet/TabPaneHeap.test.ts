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
import {TabPaneHeap} from "../../../../../dist/trace/component/trace/sheet/TabPaneHeap.js";
//@ts-ignore
import {HeapBean} from "../../../../../dist/trace/bean/HeapBean";
//@ts-ignore
import {HeapTreeDataBean} from "../../../../../dist/trace/bean/HeapTreeDataBean";
//@ts-ignore
import {queryHeapAllData} from "../../../../../dist/trace/database/SqlLite";
const sqlit = require("../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('TabPaneHeap Test', () => {
    document.body.innerHTML = `<div><tabpane-heap class="heap"></tabpane-heap></div>`
    let tabPane = document.querySelector('.heap') as TabPaneHeap;

    let tabPaneHeap = new TabPaneHeap();
    let list = [{
        AllocationSize:0,
        DeAllocationSize:0,
        RemainingSize:0,
        children:[{
            length:1
        }]
    }]
    let selection = {
        leftNs:1,
        rightNs:1
    }

    let heapTreeDataBean: Array<HeapTreeDataBean> = [{
        MoudleName: 'abc',
        AllocationFunction: 'ccc',
        startTs: 0,
        endTs: 0,
        eventType: '',
        depth: 0,
        heapSize: 0,
        eventId: "",
    },{
        MoudleName: '',
        AllocationFunction: '',
        startTs: 0,
        endTs: 0,
        eventType: '',
        depth: 0,
        heapSize: 0,
        eventId: "",
    },{
        MoudleName: '',
        AllocationFunction: '',
        startTs: 0,
        endTs: 0,
        eventType: '',
        depth: 0,
        heapSize: 0,
        eventId: "",
    }]

    let mockGetHeapAllData = sqlit.queryHeapAllData
    mockGetHeapAllData.mockResolvedValue(heapTreeDataBean);

    tabPane.data = [{
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
        statisticsSelectData: undefined,
        perfSampleIds: [],
        perfCpus: [],
        perfProcess: [],
        perfThread: [],
        perfAll: false,
    }]

    it('TabPaneHeapTest01', function () {
        let listData: Array<HeapBean> = [{
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
        }]
        expect(tabPaneHeap.setTreeDataSize(listData)).toBeUndefined();
    });

    it('TabPaneHeapTest02', function () {
        let beanList: Array<HeapBean> = [{
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
        },{
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
        }]

        let heapTreeDataBean: Array<HeapTreeDataBean> = [{
            MoudleName: '',
            AllocationFunction: '',
            startTs: 0,
            endTs: 0,
            eventType: '',
            depth: 0,
            heapSize: 0,
            eventId: "",
        },{
            MoudleName: '',
            AllocationFunction: '',
            startTs: 0,
            endTs: 0,
            eventType: '',
            depth: 0,
            heapSize: 0,
            eventId: "",
        },{
            MoudleName: '',
            AllocationFunction: '',
            startTs: 0,
            endTs: 0,
            eventType: '',
            depth: 0,
            heapSize: 0,
            eventId: "",
        }]

        let selectionData = {
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
            statisticsSelectData: undefined,
            perfSampleIds: [],
            perfCpus: [],
            perfProcess: [],
            perfThread: [],
            perfAll: false,
        }
        expect(tabPaneHeap.merageTree(1, beanList,heapTreeDataBean,selectionData)).toBeUndefined();
    });

    it('TabPaneHeapTest03', function () {
        expect(tabPaneHeap.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px;
        }
        </style>

        <lit-table id=\\"tb-heap\\" style=\\"height: auto\\" tree>
        <lit-table-column width=\\"30%\\" title=\\"Allocation Function\\" data-index=\\"AllocationFunction\\" key=\\"AllocationFunction\\" align=\\"center\\" >
        </lit-table-column>
        <lit-table-column width=\\"170px\\" title=\\"Moudle Name\\" data-index=\\"MoudleName\\" key=\\"MoudleName\\" >
        </lit-table-column>
        <lit-table-column width=\\"1fr\\" title=\\"Allocations\\" data-index=\\"Allocations\\" key=\\"Allocations\\" align=\\"center\\" >
        </lit-table-column>
        <lit-table-column width=\\"1fr\\" title=\\"Deallocations\\" data-index=\\"Deallocations\\" key=\\"Deallocations\\" align=\\"center\\" >
        </lit-table-column>
        <lit-table-column width=\\"1fr\\" title=\\"Allocation Size\\" data-index=\\"AllocationSize\\" key=\\"AllocationSize\\" align=\\"center\\" >
        </lit-table-column>
        <lit-table-column width=\\"1fr\\" title=\\"DeAllocation Size\\" data-index=\\"DeAllocationSize\\" key=\\"DeAllocationSize\\" align=\\"center\\" >
        </lit-table-column>
        <lit-table-column title=\\"Total Count\\" data-index=\\"Total\\" key=\\"Total\\" align=\\"center\\" >
        </lit-table-column>
        <lit-table-column width=\\"1fr\\" title=\\"Remaining Size\\" data-index=\\"RemainingSize\\" key=\\"RemainingSize\\" align=\\"center\\" >
        </lit-table-column>
        </lit-table>
        "
`);
    });

    it('TabPaneHeapTest04', function () {
        let beanList: Array<HeapBean> = [{
            MoudleName: 'abc',
            AllocationFunction: 'ccc',
            Allocations: 0,
            Deallocations: 0,
            AllocationSize: 0,
            DeAllocationSize: 0,
            Total: 0,
            RemainingSize: 0,
            children: [],
            depth: 0,
        },{
            MoudleName: 'abc',
            AllocationFunction: 'ccc',
            Allocations: 0,
            Deallocations: 0,
            AllocationSize: 0,
            DeAllocationSize: 0,
            Total: 0,
            RemainingSize: 0,
            children: [],
            depth: 0,
        }]

        let heapTreeDataBean: Array<HeapTreeDataBean> = [{
            MoudleName: 'abc',
            AllocationFunction: 'ccc',
            startTs: 0,
            endTs: 0,
            eventType: '',
            depth: 0,
            heapSize: 0,
            eventId: "",
        },{
            MoudleName: '',
            AllocationFunction: '',
            startTs: 0,
            endTs: 0,
            eventType: '',
            depth: 0,
            heapSize: 0,
            eventId: "",
        },{
            MoudleName: '',
            AllocationFunction: '',
            startTs: 0,
            endTs: 0,
            eventType: '',
            depth: 0,
            heapSize: 0,
            eventId: "",
        }]

        let selectionData = {
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
            statisticsSelectData: undefined,
            perfSampleIds: [],
            perfCpus: [],
            perfProcess: [],
            perfThread: [],
            perfAll: false,
        }
        expect(tabPaneHeap.merageTree(1, beanList,heapTreeDataBean,selectionData)).toBeUndefined();
    });
})