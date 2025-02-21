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
import {TabPaneSlices} from "../../../../../dist/trace/component/trace/sheet/TabPaneSlices.js"

const sqlit = require("../../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../../dist/trace/database/SqlLite.js");
describe('TabPaneSlices Test', () => {
    let tabPaneSlices = new TabPaneSlices();

    it('TabPaneSlicesTest01', function () {
        expect(tabPaneSlices.sortByColumn({
            key: 'name',
            sort: () => {
            }
        })).toBeUndefined();
    });

    it('TabPaneSlicesTest05', function () {
        expect(tabPaneSlices.sortByColumn({
            key: !'name',
            sort: () => {
            }
        })).toBeUndefined();
    });

    it('TabPaneSlicesTest02', function () {
        let mockgetTabThreadStates = sqlit.getTabSlices
        mockgetTabThreadStates.mockResolvedValue([{name : "11",
                wallDuration: 10,
                occurrences: 10,
            },{name : "22",
                wallDuration: 20,
                occurrences: 20,
            }]
        )
        let a = {rightNs: 1, leftNs: 0, funTids: [11, 12, 13]}
        expect(tabPaneSlices.data = a).toBeTruthy();
    });

    it('TabPaneSlicesTest03', function () {
        let mockgetTabThreadStates = sqlit.getTabSlices
        mockgetTabThreadStates.mockResolvedValue([])
        let a = {rightNs: 1, leftNs: 0, funTids: [11, 12, 13]}
        expect(tabPaneSlices.data = a).toBeTruthy();
    });

    it('TabPaneSlicesTest04', function () {
        expect(tabPaneSlices.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px;
        }
        </style>
        <label id=\\"time-range\\" style=\\"width: 100%;height: 20px;text-align: end;font-size: 10pt;margin-bottom: 5px\\">Selected range:0.0 ms</label>
        <lit-table id=\\"tb-slices\\" style=\\"height: auto\\">
            <lit-table-column title=\\"Name\\" width=\\"500px\\" data-index=\\"name\\" key=\\"name\\"  align=\\"flex-start\\" order>
            </lit-table-column>
            <lit-table-column title=\\"Wall duration(ms)\\" width=\\"1fr\\" data-index=\\"wallDuration\\" key=\\"wallDuration\\"  align=\\"flex-start\\" order >
            </lit-table-column>
            <lit-table-column title=\\"Avg Wall duration(ms)\\" width=\\"1fr\\" data-index=\\"avgDuration\\" key=\\"avgDuration\\"  align=\\"flex-start\\" order >
            </lit-table-column>
            <lit-table-column title=\\"Occurrences\\" width=\\"1fr\\" data-index=\\"occurrences\\" key=\\"occurrences\\"  align=\\"flex-start\\" order >
            </lit-table-column>
        </lit-table>
        "
`);
    });
})
