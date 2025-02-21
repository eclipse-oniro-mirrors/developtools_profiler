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
import {CpuFreqStruct,FreqRender, freq} from "../../../../dist/trace/database/ui-worker/ProcedureWorkerFreq.js";
// @ts-ignore
import {Rect} from "../../../../dist/trace/component/trace/timer-shaft/Rect.js";

describe('freqTest', () => {

    it('freqTest01', () => {
        let dataList = new Array();
        dataList.push({startTime: 0, dur: 10, frame: {x:0, y:9, width:10, height:10}})
        dataList.push({startTime: 1, dur: 111})
        let rect = new Rect(0, 10, 10, 10);
        freq(dataList, new Set(), 1, 100254, 100254, rect)
    })

    it('freqTest02', () => {
        let dataList = new Array();
        dataList.push({startTime: 0, dur: 10, frame: {x:0, y:9, width:10, height:10}})
        dataList.push({startTime: 1, dur: 111, frame: {x:0, y:9, width:10, height:10}})
        let rect = new Rect(0, 10, 10, 10);
        freq(dataList, new Set(), 1, 100254, 100254, rect)
    })

    it('freqTest03', () => {
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

        expect(CpuFreqStruct.draw(ctx, data)).toBeUndefined()

    })
    it('freqTest04', () => {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        const Sourcedata = {
            frame: {
                x: 20,
                y: 20,
                width: 100,
                height: 100
            },
            maxFreq: 200,
            value: 50
        }
        expect(CpuFreqStruct.draw(ctx,Sourcedata)).toBeUndefined()})

    it('freqTest05', function () {
        let freqRender = new FreqRender()
        let  req = {
            lazyRefresh:true,
            type:"",
            startNS:1,
            endNS:1,
            totalNS:1,
            frame: {
                x: 20,
                y: 20,
                width: 100,
                height: 100
            },
            useCache:false,
            range:{
                refresh:"",
            },
            canvas:'',
            context:{
                font:"11px sans-serif",
                fillStyle:"#ec407a",
                globalAlpha:0.6,
                height:150,
                width:100
            },
            lineColor:'',
            isHover:'',
            hoverX:1,
            wakeupBean:undefined,
            flagMoveInfo:'',
            flagSelectedInfo:'',
            slicesTime:3,
            id:1,
            x: 20,
            y: 20,
            width: 100,
            height: 100,
            params:{
                isLive:false,
                maxHeight:2,
                dpr:1,
                hoverFuncStruct:'',
                selectFuncStruct:undefined,
            }
        }
        window.postMessage = jest.fn(()=>true)
        expect(freqRender.render(req,[],[])).toBeUndefined()
    });

});