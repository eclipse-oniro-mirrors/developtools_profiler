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
import {TabPaneHistoryProcesses} from "../../../../../dist/trace/component/trace/sheet/TabPaneHistoryProcesses.js";
window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('TabPaneHistoryProcesses Test', function () {

    let tabPaneHistoryProcesses = new TabPaneHistoryProcesses();
    it('TabPaneHistoryProcessesTest01 ', function () {
        tabPaneHistoryProcesses.queryResult.length = 1;
        expect(tabPaneHistoryProcesses.filterData()).toBeUndefined();
    });

    it('TabPaneHistoryProcessesTest02 ', function () {
        const val = {
            processId:-1,
            processName:"",
            alive:"",
            firstSeen:"",
            lastSeen:"",
            responsibleProcess:"",
            userName:"",
            cpuTime:""
        }
        expect(tabPaneHistoryProcesses.toProcessHistoryArray(val)).not.toBeUndefined();
    });

    it('TabPaneHistoryProcessesTest03 ', function () {
        expect(tabPaneHistoryProcesses.sortByColumn({
            key:'startTime',
        })).toBeUndefined();
    });

    it('TabPaneHistoryProcessesTest04 ', function () {
        expect(tabPaneHistoryProcesses.sortByColumn({
            key:'alive',
        })).toBeUndefined();
    });

    it('TabPaneHistoryProcessesTest05 ', function () {
        expect(tabPaneHistoryProcesses.sortByColumn({
            key:!'startTime'&&!'alive',
        })).toBeUndefined();
    });

});