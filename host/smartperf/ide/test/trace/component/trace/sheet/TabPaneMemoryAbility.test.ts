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
import {TabPaneMemoryAbility} from "../../../../../dist/trace/component/trace/sheet/TabPaneMemoryAbility.js";
window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('TabPaneMemoryAbility Test', () => {
    let tabPaneMemoryAbility = new TabPaneMemoryAbility();

    it('TabPaneMemoryAbilityTest01', function () {
        tabPaneMemoryAbility.queryResult.length = 1;
        expect(tabPaneMemoryAbility.filterData()).toBeUndefined();
    });

    it('TabPaneMemoryAbilityTest02', function () {
        const systemMemorySummary = [{
            startTimeStr:"1",
            durationStr:"1",
            cached:"1",
            swapTotal:"1"
        }]
        expect(tabPaneMemoryAbility.toMemoryAbilityArray(systemMemorySummary)).not.toBeUndefined();
    });

    it('TabPaneMemoryAbilityTest03', function () {
        expect(tabPaneMemoryAbility.sortByColumn({
            key:'startTime'
        })).toBeUndefined();
    });

    it('TabPaneMemoryAbilityTest04', function () {
        expect(tabPaneMemoryAbility.sortByColumn({
            key:!'startTime'
        })).toBeUndefined();
    });
})