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
import {SpSdkChart} from "../../../../dist/trace/component/chart/SpSdkChart.js"
const sqlit = require("../../../../dist/trace/database/SqlLite.js")
jest.mock("../../../../dist/trace/database/SqlLite.js");

window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(() => ({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}));

describe('SpSdkChart Test', ()=> {
    let spSdkChart = new SpSdkChart();
    let MockStartTime = sqlit.queryStartTime;
    MockStartTime.mockResolvedValue([{
        start_ts:0
    }])
    it('SpSdkChartTest01', function () {
        let showType = {
            columns:[{showType: 'counter'}]
        }
        expect(spSdkChart.getTableType(showType)).toBe("");
    });

    it('SpSdkChartTest02', function () {
        expect(spSdkChart.createSliceSql(10,8,[{length:5}],"")).toBe("select undefined from 8 ");
    });

    it('SpSdkChartTest03', function () {
        expect(spSdkChart.createMaxValueSql("","")).toBe("select max(value) as max_value from  ");
    });

    it('SpSdkChartTest04', function () {
        expect(spSdkChart.createMaxValueSql("a","c")).toBe("select max(value) as max_value from a c");
    });

    it('SpSdkChartTest06', function () {
        expect(spSdkChart.createSql(3,"c",[{length:3}],"a")).toBe("select undefined from c a");
    });

    it('SpSdkChartTest07', function () {
        expect(spSdkChart.createSql(0,"c",[{length:3}],"")).toBe("select undefined from c ");
    });

    it('SpSdkChartTest08', function () {
        spSdkChart.init()
        expect(spSdkChart).toBeDefined();
    });

    it('SpSdkChartTest09', function () {
        let showType = {
            columns:[{showType: 'slice'}]
        }
        expect(spSdkChart.getTableType(showType)).toBe("");
    });

})