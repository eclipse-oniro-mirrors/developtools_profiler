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
import {mem, ProcessMemStruct} from "../../../dist/trace/database/ProcedureWorkerMem.js";
// @ts-ignore
import {Rect} from "../../../dist/trace/component/trace/timer-shaft/Rect.js";

describe(' Test', () => {

    it('MemTest01', () => {
        let dataList = new Array();
        dataList.push({startTime: 0, duration: 10, frame: {x:0, y:9, width:10, height:10}})
        dataList.push({startTime: 1, duration: 111})
        let rect = new Rect(0, 10, 10, 10);
        mem(dataList, new Set(), 1, 100254, 100256, rect)
    })

    it('MemTest02', () => {
        let dataList = new Array();
        dataList.push({startTime: 0, duration: 10, frame: {x:0, y:9, width:10, height:10}})
        dataList.push({startTime: 1, duration: 111, frame: {x:0, y:9, width:10, height:10}})
        let rect = new Rect(0, 10, 10, 10);
        mem(dataList, new Set(), 2, 100254, 100254, rect)
    })

    it('MemTest03', () => {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');

        const data = {
            frame: {
                x: 20,
                y: 20,
                width: 100,
                height: 100
            },
            startNS: 200,
            value: 50
        }
        expect(ProcessMemStruct.draw(ctx, data)).toBeUndefined()
    })


    // it('MemTest03', () => {
    //     setMemFrame(dataList, new Set(), 1, 100254, 100254, rect)
    // })

});