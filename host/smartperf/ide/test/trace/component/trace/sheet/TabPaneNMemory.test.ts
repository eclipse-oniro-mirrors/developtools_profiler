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
import {TabPaneNMemory} from "../../../../../dist/trace/component/trace/sheet/TabPaneNMemory.js"

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('TabPaneNMemory Test', () => {
    let tabPaneNMemory = new TabPaneNMemory();
    let val={
        statisticsSelectData:{
            memoryTap:1
        }
    }
    let hook={eventId:1}

    it('TabPaneNMemoryTest01', function () {
        expect(tabPaneNMemory.getTypeFromIndex(-1)).not.toBeUndefined();
    });

    it('TabPaneNMemoryTest02', function () {
        expect(tabPaneNMemory.getTypeFromIndex(0)).not.toBeUndefined();
    });

    it('TabPaneNMemoryTest03', function () {
        expect(tabPaneNMemory.getTypeFromIndex(1,{eventType:"AllocEvent"})).not.toBeUndefined();
    });

    it('TabPaneNMemoryTest04', function () {
        expect(tabPaneNMemory.getTypeFromIndex(2,{eventType:"MmapEvent"})).not.toBeUndefined();
    });

    it('TabPaneNMemoryTest05', function () {
        expect(tabPaneNMemory.handleQueryResult([1])).not.toBeUndefined();
    });

    it('TabPaneNMemoryTest06', function () {
        expect(tabPaneNMemory.initFilterTypes()).toBeUndefined();
    });

    it('TabPaneNMemoryTest07', function () {
        expect(tabPaneNMemory.filterQueryData()).toBeUndefined();
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
        </style>
        <div style=\\"display: flex;flex-direction: row\\">
           <div style=\\"width: 65%\\">
                <lit-table id=\\"tb-native-memory\\" style=\\"height: auto\\">
                    <lit-table-column width=\\"40px\\" title=\\"#\\" data-index=\\"index\\" key=\\"index\\"  align=\\"flex-start\\">
                    </lit-table-column>
                    <lit-table-column width=\\"1fr\\" title=\\"Address\\" data-index=\\"addr\\" key=\\"addr\\"  align=\\"flex-start\\">
                    </lit-table-column>
                    <lit-table-column width=\\"1fr\\" title=\\"Memory Type\\" data-index=\\"eventType\\" key=\\"eventType\\"  align=\\"flex-start\\">
                    </lit-table-column>
                    <lit-table-column width=\\"1fr\\" title=\\"Timestamp\\" data-index=\\"timestamp\\" key=\\"timestamp\\"  align=\\"flex-start\\">
                    </lit-table-column>
                    <lit-table-column width=\\"1fr\\" title=\\"Size\\" data-index=\\"heapSizeUnit\\" key=\\"heapSizeUnit\\"  align=\\"flex-start\\">
                    </lit-table-column>
                    <lit-table-column width=\\"20%\\" title=\\"Responsible Library\\" data-index=\\"library\\" key=\\"library\\"  align=\\"flex-start\\">
                    </lit-table-column>
                    <lit-table-column width=\\"20%\\" title=\\"Responsible Caller\\" data-index=\\"symbol\\" key=\\"symbol\\"  align=\\"flex-start\\">
                    </lit-table-column>
                </lit-table>
                <tab-pane-filter id=\\"filter\\" mark first second></tab-pane-filter>
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

    it('TabPaneNMemoryTest09', function () {
        tabPaneNMemory.tblData = jest.fn(()=>undefined)
        tabPaneNMemory.tblData.recycleDataSource = jest.fn(()=>true)
        expect(tabPaneNMemory.setRightTableData()).toBeUndefined();
    });
})