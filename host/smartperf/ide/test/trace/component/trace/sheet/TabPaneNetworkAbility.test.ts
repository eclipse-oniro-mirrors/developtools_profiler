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
import {TabPaneNetworkAbility} from "../../../../../dist/trace/component/trace/sheet/TabPaneNetworkAbility.js";
window.ResizeObserver = window.ResizeObserver || jest.fn().mockImplementation(()=>({
    disconnect: jest.fn(),
    observe: jest.fn(),
    unobserve: jest.fn(),
}))

describe('TabPaneNetworkAbility Test', ()=>{

    let tabPaneNetworkAbility = new TabPaneNetworkAbility();
    it('TabPaneNetworkAbilityTest01',()=>{
        tabPaneNetworkAbility.queryResult.length = 1;
        expect(tabPaneNetworkAbility.filterData()).toBeUndefined();
    });

    it('TabPaneNetworkAbilityTest02 ', function () {
        const val = {
            startTimeStr:"",
            durationStr:"",
            dataReceivedStr:"",
            dataReceivedSecStr:"",
            dataSendSecStr:"",
            dataSendStr:"",
            packetsIn:-1,
            packetsOut:-1,
            packetsOutSec:-1
        }
        expect(tabPaneNetworkAbility.toNetWorkAbilityArray(val)).not.toBeUndefined();
    });

    it('TabPaneNetworkAbilityTest03 ', function () {
        expect(tabPaneNetworkAbility.sortByColumn({
            key:'startTime',
        })).toBeUndefined();
    });

    it('TabPaneNetworkAbilityTest04 ', function () {
        expect(tabPaneNetworkAbility.sortByColumn({
            key:!'startTime',
        })).toBeUndefined();
    });
})