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

export function freq(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
    if (use && res.length > 0) {
        res.forEach(it => CpuFreqStruct.setFreqFrame(it, 5, startNS || 0, endNS || 0, totalNS || 0, frame));
        return;
    }
    res.length = 0;
    if (list) {
        for (let i = 0, len = list.length; i < len; i++) {
            let it = list[i];
            if (i === list.length - 1) {
                it.dur = (endNS || 0) - (it.startNS || 0)
            } else {
                it.dur = (list[i + 1].startNS || 0) - (it.startNS || 0)
            }
            if ((it.startNS || 0) + (it.dur || 0) > (startNS || 0) && (it.startNS || 0) < (endNS || 0)) {
                CpuFreqStruct.setFreqFrame(list[i], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                if (i > 0 && ((list[i - 1].frame?.x || 0) == (list[i].frame?.x || 0) && (list[i - 1].frame?.width || 0) == (list[i].frame?.width || 0))) {

                } else {
                    res.push(it)
                }
            }
        }
    }

}

export class CpuFreqStruct extends BaseStruct {
    static maxFreq: number = 0
    static maxFreqName: string = "0 GHz"
    static hoverCpuFreqStruct: CpuFreqStruct | undefined;
    static selectCpuFreqStruct: CpuFreqStruct | undefined;
    cpu: number | undefined
    value: number | undefined
    startNS: number | undefined
    dur: number | undefined //自补充，数据库没有返回

    static draw(ctx: CanvasRenderingContext2D, data: CpuFreqStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            let index = data.cpu || 0
            index += 2
            ctx.fillStyle = ColorUtils.colorForTid(index)
            ctx.strokeStyle = ColorUtils.colorForTid(index)
            if (data.startNS === CpuFreqStruct.hoverCpuFreqStruct?.startNS) {
                ctx.lineWidth = 1;
                ctx.globalAlpha = 0.6;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / CpuFreqStruct.maxFreq);
                ctx.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
                ctx.beginPath()
                ctx.arc(data.frame.x, data.frame.y + data.frame.height - drawHeight, 3, 0, 2 * Math.PI, true)
                ctx.fill()
                ctx.globalAlpha = 1.0;
                ctx.stroke();
                ctx.beginPath()
                ctx.moveTo(data.frame.x + 3, data.frame.y + data.frame.height - drawHeight);
                ctx.lineWidth = 3;
                ctx.lineTo(data.frame.x + width, data.frame.y + data.frame.height - drawHeight)
                ctx.stroke();
            } else {
                ctx.globalAlpha = 0.6;
                ctx.lineWidth = 1;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0)) / CpuFreqStruct.maxFreq);
                ctx.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
            }
        }
        ctx.globalAlpha = 1.0;
        ctx.lineWidth = 1;
    }

    static setFreqFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let x1: number, x2: number;
        if ((node.startNS || 0) < startNS) {
            x1 = 0;
        } else {
            x1 = ns2x((node.startNS || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startNS || 0) + (node.dur || 0) > endNS) {
            x2 = frame.width;
        } else {
            x2 = ns2x((node.startNS || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
        }
        let getV: number = x2 - x1 <= 1 ? 1 : x2 - x1;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.floor(x1);
        node.frame.y = frame.y + padding;
        node.frame.width = Math.ceil(getV);
        node.frame.height = Math.floor(frame.height - padding * 2);
    }
}

const textPadding = 2;