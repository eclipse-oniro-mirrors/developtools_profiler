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
import {hiPerfThread,HiPerfThreadStruct} from "../../../dist/trace/database/ProcedureWorkerHiPerfThread.js";

describe('ProcedureWorkerHiPerfCPU Test', ()=>{

    it('ProcedureWorkerHiPerfCPUTest01',()=>{
        const data = {
            frame:undefined,
            cpu:1,
            startNs:1,
            value:1,
        }
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        expect(HiPerfThreadStruct.draw(ctx,'',data,true)).toBeUndefined();
    });

    it('ProcedureWorkerHiPerfCPUTest02', function () {
        let dataList = new Array();
        dataList.push({startNS: 0, dur: 10,length:1, frame: {x:0, y:9, width:10, height:10}})
        dataList.push({startNS: 1, dur: 2,length:1})
        hiPerfThread(dataList, new Set(), 1, 8, 3, "",true)
    });

    it('ProcedureWorkerHiPerfCPUTest03', function () {
        let dataList = new Array();
        dataList.push({startNS: 0, dur: 10,length:1, frame: {x:0, y:9, width:10, height:10}})
        dataList.push({startNS: 1, dur: 2,length:1})
        hiPerfThread(dataList, new Set(), 1, 8, 3, "",false)
    });
})