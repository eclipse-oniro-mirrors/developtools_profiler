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
import {TimeRuler} from "../../../../../dist/trace/component/trace/timer-shaft/TimeRuler.js"
// @ts-ignore
import {TimerShaftElement} from "../../../../../dist/trace/component/trace/TimerShaftElement.js";

describe('TimeRuler Test', ()=>{
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d');
    document.body.innerHTML = '<timer-shaft-element id="timerShaftEL"><timer-shaft-element>'

    let timerShaftElement = document.querySelector('#timerShaftEL') as TimerShaftElement;

    let timeRuler = new TimeRuler(timerShaftElement ,{
        x: 20,
        y: 20,
        width: 100,
        height: 100
    }, 10000000000);

    it('TimeRulerTest01', function () {
        expect(timeRuler.draw()).toBeUndefined();
    });
})
