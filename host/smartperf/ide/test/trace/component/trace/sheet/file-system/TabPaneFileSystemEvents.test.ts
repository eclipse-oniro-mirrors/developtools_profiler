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

import  "../../../../../../dist/trace/component/trace/sheet/file-system/TabPaneFileSystemEvents.js"

// @ts-ignore
import {TabPaneFileSystemEvents} from "../../../../../../dist/trace/component/trace/sheet/file-system/TabPaneFileSystemEvents.js"
// @ts-ignore
import {TabPaneFilter} from "../../../../../../dist/trace/component/trace/sheet/TabPaneFilter.js";

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));
describe('TabPaneFileSystemEvents Test', () => {
    document.body.innerHTML = `<tabpane-filesystem-event id="files"></tabpane-filesystem-event>`
    let tabPaneFileSystemEvents = document.querySelector("#files") as TabPaneFileSystemEvents
    it('TabPaneFileStatisticsTest01', function () {
        expect(tabPaneFileSystemEvents.sortTable("",0)).toBeUndefined();
    });

    it('TabPaneFileStatisticsTest02', function () {
        tabPaneFileSystemEvents.filterSource = [{startTsStr:1}]
        expect(tabPaneFileSystemEvents.sortTable("startTsStr",1)).toBeUndefined();
    });

    it('TabPaneFileStatisticsTest03', function () {
        tabPaneFileSystemEvents.filterSource = [{durStr:1}]

        expect(tabPaneFileSystemEvents.sortTable("durStr",1)).toBeUndefined();
    });

    it('TabPaneFileStatisticsTest04', function () {
        tabPaneFileSystemEvents.filterSource = [{process:1}]

        expect(tabPaneFileSystemEvents.sortTable("process",2)).toBeUndefined();
    });

    it('TabPaneFileStatisticsTest05', function () {
        tabPaneFileSystemEvents.filterSource = [{thread:1}]

        expect(tabPaneFileSystemEvents.sortTable("thread",2)).toBeUndefined();
    });

    it('TabPaneFileStatisticsTest06', function () {
        tabPaneFileSystemEvents.filterSource = [{typeStr:1}]

        expect(tabPaneFileSystemEvents.sortTable("typeStr",2)).toBeUndefined();
    });
})