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
    ns2x, PerfRender, Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class MemRender extends Render{
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            mem(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                mem(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startTime, arr[arr.length - 1].startTime + arr[arr.length - 1].dur)
            }
            req.context.beginPath();
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            ProcessMemStruct.hoverProcessMemStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        ProcessMemStruct.hoverProcessMemStruct = re;
                        break;
                    }
                }
            } else {
                ProcessMemStruct.hoverProcessMemStruct = req.params.hoverProcessMemStruct;
            }
            for (let re of filter) {
                ProcessMemStruct.draw(req.context, re)
            }
            drawSelection(req.context, req.params);
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: ProcessMemStruct.hoverProcessMemStruct
        });
    }
}

function setMemFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
    let x1: number;
    let x2: number;
    if ((node.startTime || 0) <= startNS) {
        x1 = 0;
    } else {
        x1 = ns2x((node.startTime || 0), startNS, endNS, totalNS, frame);
    }
    if ((node.startTime || 0) + (node.duration || 0) >= endNS) {
        x2 = frame.width;
    } else {
        x2 = ns2x((node.startTime || 0) + (node.duration || 0), startNS, endNS, totalNS, frame);
    }
    let getV: number = x2 - x1 <= 1 ? 1 : x2 - x1;
    if (!node.frame) {
        node.frame = {};
    }
    node.frame.x = Math.floor(x1);
    node.frame.y = Math.floor(frame.y + padding);
    node.frame.width = Math.ceil(getV);
    node.frame.height = Math.floor(frame.height - padding * 2);
}

export function mem(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
    if (use && res.length > 0) {
        for (let i = 0, len = res.length; i < len; i++) {
            if ((res[i].startTime || 0) + (res[i].duration || 0) > startNS && (res[i].startTime || 0) < endNS) {
                setMemFrame(res[i], 5, startNS, endNS, totalNS, frame)
            }else{
                res[i].frame = null;
            }
        }
        return;
    }
    res.length = 0;
    if (list) {
        for (let i = 0, len = list.length; i < len; i++) {
            let it = list[i];
            if ((it.startTime || 0) + (it.duration || 0) > startNS && (it.startTime || 0) < endNS) {
                setMemFrame(list[i], 5, startNS, endNS, totalNS, frame)
                if (i > 0 && ((list[i - 1].frame?.x || 0) == (list[i].frame?.x || 0) && (list[i - 1].frame?.width || 0) == (list[i].frame?.width || 0))) {

                } else {
                    res.push(list[i])
                }
            }
        }
    }
}

export class ProcessMemStruct extends BaseStruct {
    static hoverProcessMemStruct: ProcessMemStruct | undefined;
    trackId: number | undefined
    processName: string | undefined
    pid: number | undefined
    upid: number | undefined
    trackName: string | undefined
    type: string | undefined
    track_id: string | undefined
    value: number | undefined
    startTime: number | undefined
    duration: number | undefined
    maxValue: number | undefined
    delta: number | undefined;

    static draw(ctx: CanvasRenderingContext2D, data: ProcessMemStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            ctx.fillStyle = ColorUtils.colorForTid(data.maxValue || 0)
            ctx.strokeStyle = ColorUtils.colorForTid(data.maxValue || 0)
            if (data.track_id === ProcessMemStruct.hoverProcessMemStruct?.track_id && data.startTime === ProcessMemStruct.hoverProcessMemStruct?.startTime) {
                ctx.lineWidth = 1;
                ctx.globalAlpha = 0.6;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / (data.maxValue || 0));
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
                let drawHeight: number = ((data.value || 0) * (data.frame.height || 0) * 1.0) / (data.maxValue || 1);
                ctx.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
            }
        }
        ctx.globalAlpha = 1.0;
        ctx.lineWidth = 1;
    }
}