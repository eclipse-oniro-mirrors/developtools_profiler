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
import {TabpanePerfProfile} from "../../../../../dist/trace/component/trace/sheet/TabPerfProfile.js"
//@ts-ignore
import {perfDataQuery} from "../../../../../dist/trace/component/hiperf/PerfDataQuery.js";

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('TabPerfProfile Test', () => {

    document.body.innerHTML = `<tabpane-perf-profile id="perfprofile"></tabpane-perf-profile>`
    let tabpanePerfProfile = document.querySelector('#perfprofile') as TabpanePerfProfile

    it('TabpanePerfProfileTest01 ', function () {
        TabpanePerfProfile.getParentTree = jest.fn(()=>true)
        expect(tabpanePerfProfile.getParentTree([],{},[])).not.toBeUndefined();
    });

    it('TabpanePerfProfileTest02 ', function () {
        expect(tabpanePerfProfile.getChildTree([],"1",[])).not.toBeUndefined();
    });

    it('TabpanePerfProfileTest03 ', function () {
        let call = {
            id:"1",
            dur:1,
            children:[]
        }
        expect(tabpanePerfProfile.setRightTableData(call)).toBeUndefined();
    });

    it('TabpanePerfProfileTest04 ', function () {
        expect(tabpanePerfProfile.filterSampleIds(true,"1","112")).not.toBeUndefined();
    });

    it('TabpanePerfProfileTest05 ', function () {
        expect(tabpanePerfProfile.hideSystemLibrary()).toBeUndefined();
    });

    it('TabpanePerfProfileTest06 ', function () {
        let startNum = 1
        let endNum = "∞"
        expect(tabpanePerfProfile.hideNumMaxAndMin(startNum,endNum)).toBeUndefined();
    });
})