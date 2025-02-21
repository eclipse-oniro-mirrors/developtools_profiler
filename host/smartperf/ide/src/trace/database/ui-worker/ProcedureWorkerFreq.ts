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

import { ColorUtils } from "../../component/trace/base/ColorUtils.js";
import {
    BaseStruct,
    drawFlagLine,
    drawLines,
    drawLoading,
    drawSelection, drawWakeUp,
    ns2x, Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class FreqRender extends Render{
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            freq(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                freq(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            req.context.beginPath();
            CpuFreqStruct.maxFreq = req.params.maxFreq;
            CpuFreqStruct.maxFreqName = req.params.maxFreqName;
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            CpuFreqStruct.hoverCpuFreqStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        CpuFreqStruct.hoverCpuFreqStruct = re;
                        break;
                    }
                }
            } else {
                CpuFreqStruct.hoverCpuFreqStruct = req.params.hoverCpuFreqStruct;
            }
            CpuFreqStruct.selectCpuFreqStruct = req.params.selectCpuFreqStruct;
            for (let re of filter) {
                CpuFreqStruct.draw(req.context, re)
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            let s = CpuFreqStruct.maxFreqName
            let textMetrics = req.context.measureText(s);
            req.context.globalAlpha = 0.8
            req.context.fillStyle = "#f0f0f0"
            req.context.fillRect(0, 5, textMetrics.width + 8, 18)
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText(s, 4, 5 + 9)
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame);
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: CpuFreqStruct.hoverCpuFreqStruct
        });
    }
}

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
            if (data.startNS === CpuFreqStruct.hoverCpuFreqStruct?.startNS||data.startNS === CpuFreqStruct.selectCpuFreqStruct?.startNS) {
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