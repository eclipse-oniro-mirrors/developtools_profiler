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
import {TabPaneDiskAbility} from "../../../../../dist/trace/component/trace/sheet/TabPaneDiskAbility.js";
window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(()=>({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}))

describe('TabPaneDiskAbility Test', ()=>{

    let tabPaneDiskAbility = new TabPaneDiskAbility();
    it('TabPaneDiskAbilityTest01',()=>{
        tabPaneDiskAbility.queryResult.length = 1;
        expect(tabPaneDiskAbility.filterData()).toBeUndefined();
    });

    it('TabPaneDiskAbilityTest02 ', function () {
        const val = {
            startTimeStr:"",
            durationStr:"",
            dataReadStr:"",
            dataReadSecStr:"",
            dataWriteStr:"",
            readsInStr:"",
            readsInSecStr:"",
            writeOutStr:"",
            writeOutSecStr:""
        }
        expect(tabPaneDiskAbility.toDiskAbilityArray(val)).not.toBeUndefined();
    });

    it('TabPaneDiskAbilityTest03 ', function () {
        expect(tabPaneDiskAbility.sortByColumn({
            key:'startTime',
        })).toBeUndefined();
    });

    it('TabPaneDiskAbilityTest04 ', function () {
        expect(tabPaneDiskAbility.sortByColumn({
            key:!'startTime',
        })).toBeUndefined();
    });
})