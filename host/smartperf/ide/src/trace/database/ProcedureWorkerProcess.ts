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

import {BaseStruct, ColorUtils, ns2x} from "./ProcedureWorkerCommon.js";
import {CpuStruct} from "./ProcedureWorkerCPU.js";

export function proc(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any,use:boolean) {
    if(use && res.length > 0){
        res.forEach(it=>ProcessStruct.setProcessFrame(it, 5, startNS || 0, endNS || 0, totalNS || 0, frame))
        return;
    }
    res.length = 0 ;
    if (list) {
        for (let i = 0, len = list.length; i < len; i++) {
            let it = list[i];
            if ((it.startTime || 0) + (it.dur || 0) > (startNS || 0) && (it.startTime || 0) < (endNS || 0)) {
                ProcessStruct.setProcessFrame(list[i], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                if (i > 0 && ((list[i - 1].frame?.x || 0) == (list[i].frame?.x || 0) && (list[i - 1].frame?.width || 0) == (list[i].frame?.width || 0))) {

                } else {
                    res.push(list[i])
                }
            }
        }
    }
}

const padding = 1;

export class ProcessStruct extends BaseStruct {
    cpu: number | undefined
    dur: number | undefined
    id: number | undefined
    pid: number | undefined
    process: string | undefined
    startTime: number | undefined
    state: string | undefined
    thread: string | undefined
    tid: number | undefined
    ts: number | undefined
    type: string | undefined
    utid: number | undefined

    static draw(ctx: CanvasRenderingContext2D,path:Path2D, data: ProcessStruct,miniHeight:number) {
        if (data.frame) {
            path.rect(data.frame.x, data.frame.y + (data.cpu || 0) * miniHeight + padding, data.frame.width, miniHeight)
        }
    }

    static setFrame(node: any, pns: number, startNS: number, endNS: number, frame: any) {
        if ((node.startTime || 0) < startNS) {
            node.frame.x = 0;
        } else {
            node.frame.x = Math.floor(((node.startTime || 0) - startNS) / pns);
        }
        if ((node.startTime || 0) + (node.dur || 0) > endNS) {
            node.frame.width = frame.width - node.frame.x;
        } else {
            node.frame.width = Math.ceil(((node.startTime || 0) + (node.dur || 0) - startNS) / pns - node.frame.x);
        }
        if (node.frame.width < 1) {
            node.frame.width = 1;
        }
    }

    static setProcessFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let x1: number;
        let x2: number;
        if ((node.startTime || 0) < startNS) {
            x1 = 0;
        } else {
            x1 = ns2x((node.startTime || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startTime || 0) + (node.dur || 0) > endNS) {
            x2 = frame.width;
        } else {
            x2 = ns2x((node.startTime || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
        }
        let getV: number = x2 - x1 <= 1 ? 1 : x2 - x1;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.floor(x1);
        node.frame.y = Math.floor(frame.y + 2);
        node.frame.width = Math.ceil(getV);
        node.frame.height = Math.floor(frame.height - padding * 2);
    }
}