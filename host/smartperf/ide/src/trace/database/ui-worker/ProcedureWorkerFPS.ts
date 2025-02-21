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

import {
    BaseStruct, drawFlagLine,
    drawLines,
    drawLoading,
    drawSelection, drawWakeUp,
    ns2x,
    Rect, Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class FpsRender extends Render{
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            fps(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                fps(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            req.context.beginPath();
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            FpsStruct.hoverFpsStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        FpsStruct.hoverFpsStruct = re;
                        break;
                    }
                }
            } else {
                FpsStruct.hoverFpsStruct = req.params.hoverFpsStruct;
            }
            for (let re of filter) {
                FpsStruct.draw(req.context, re)
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            let maxFps = FpsStruct.maxFps + "FPS"
            let textMetrics = req.context.measureText(maxFps);
            req.context.globalAlpha = 0.8
            req.context.fillStyle = "#f0f0f0"
            req.context.fillRect(0, 5, textMetrics.width + 8, 18)
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText(maxFps, 4, 5 + 9);
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame);
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: FpsStruct.hoverFpsStruct
        });
    }
}

export function fps(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
    if (use && res.length > 0) {
        res.forEach(it => FpsStruct.setFrame(it, 5, startNS, endNS, totalNS, frame));
        return;
    }
    FpsStruct.maxFps = 0
    res.length = 0;
    if (list) {
        for (let i = 0, len = list.length; i < len; i++) {
            let it = list[i];
            if ((it.fps || 0) > FpsStruct.maxFps) {
                FpsStruct.maxFps = it.fps || 0
            }
            if (i === list.length - 1) {
                it.dur = (endNS || 0) - (it.startNS || 0)
            } else {
                it.dur = (list[i + 1].startNS || 0) - (it.startNS || 0)
            }
            if ((it.startNS || 0) + (it.dur || 0) > (startNS) && (it.startNS || 0) < (endNS)) {
                FpsStruct.setFrame(list[i], 5, startNS, endNS, totalNS, frame)
                if (i > 0 && ((list[i - 1].frame?.x || 0) == (list[i].frame?.x || 0) && (list[i - 1].frame?.width || 0) == (list[i].frame?.width || 0))) {

                } else {
                    res.push(list[i])
                }
            }
        }
    }
}

export class FpsStruct extends BaseStruct {
    static maxFps: number = 0
    static maxFpsName: string = "0 FPS"
    static hoverFpsStruct: FpsStruct | undefined;
    static selectFpsStruct: FpsStruct | undefined;
    fps: number | undefined
    startNS: number | undefined = 0
    dur: number | undefined //自补充，数据库没有返回

    static draw(ctx: CanvasRenderingContext2D, data: FpsStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            ctx.fillStyle = '#535da6'
            ctx.strokeStyle = '#535da6'
            if (data.startNS === FpsStruct.hoverFpsStruct?.startNS) {
                ctx.lineWidth = 1;
                ctx.globalAlpha = 0.6;
                let drawHeight: number = ((data.fps || 0) * (data.frame.height || 0) * 1.0) / FpsStruct.maxFps;
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
                let drawHeight: number = ((data.fps || 0) * (data.frame.height || 0) * 1.0) / FpsStruct.maxFps;
                ctx.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
            }
        }
        ctx.globalAlpha = 1.0;
        ctx.lineWidth = 1;
    }

    static setFrame(node: FpsStruct, padding: number, startNS: number, endNS: number, totalNS: number, frame: Rect) {
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
        let rectangle: Rect = new Rect(Math.floor(x1), Math.ceil(frame.y + padding), Math.ceil(getV), Math.floor(frame.height - padding * 2));
        node.frame = rectangle;
    }
}

const textPadding = 2;