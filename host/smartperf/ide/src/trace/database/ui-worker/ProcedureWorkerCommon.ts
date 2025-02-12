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

import {CpuStruct, WakeupBean} from "./ProcedureWorkerCPU.js";

export abstract class Render {
    abstract render(req: RequestMessage, list: Array<any>, filter: Array<any>): void;
}

export abstract class PerfRender {
    abstract render(req: RequestMessage, list: Array<any>, filter: Array<any>, dataList2: Array<any>): void;
}

export class RequestMessage {
    type: string | undefined | null
    lazyRefresh: boolean | undefined;
    intervalPerf: any;
    canvas: any;
    context: any;
    params: any;
    online: any;
    buf: any;
    isRangeSelect: any;
    isHover: any;
    xs: any;
    frame: any;
    flagMoveInfo: any;
    flagSelectedInfo: any;
    hoverX: any;
    hoverY: any;
    startNS: any;
    endNS: any;
    totalNS: any;
    slicesTime: { startTime: number | null, endTime: number | null, color: string | null } | undefined;
    range: any;
    scale: any;
    chartColor:any;
    canvasWidth: any;
    canvasHeight: any;
    useCache: any;
    lineColor: any;
    wakeupBean: WakeupBean | undefined | null;
    id: any;
    postMessage: { (message: any, targetOrigin: string, transfer?: Transferable[]): void; (message: any, options?: WindowPostMessageOptions): void } | undefined;
}

export function ns2s(ns: number): string {
    let second1 = 1_000_000_000; // 1 second
    let millisecond1 = 1_000_000; // 1 millisecond
    let microsecond1 = 1_000; // 1 microsecond
    let nanosecond1 = 1000.0;
    let res;
    if (ns >= second1) {
        res = (ns / 1000 / 1000 / 1000).toFixed(1) + " s";
    } else if (ns >= millisecond1) {
        res = (ns / 1000 / 1000).toFixed(1) + " ms";
    } else if (ns >= microsecond1) {
        res = (ns / 1000).toFixed(1) + " μs";
    } else if (ns > 0) {
        res = ns.toFixed(1) + " ns";
    } else {
        res = ns.toFixed(1) + " s";
    }
    return res;
}

export function ns2x(ns: number, startNS: number, endNS: number, duration: number, rect: any) {
    // @ts-ignore
    if (endNS == 0) {
        endNS = duration;
    }
    let xSize: number = (ns - startNS) * rect.width / (endNS - startNS);
    if (xSize < 0) {
        xSize = 0;
    } else if (xSize > rect.width) {
        xSize = rect.width;
    }
    return xSize;
}

export class Rect {
    x: number = 0
    y: number = 0
    width: number = 0
    height: number = 0

    constructor(x: number, y: number, width: number, height: number) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    static contains(rect: Rect, x: number, y: number): boolean {
        return rect.x <= x && x <= rect.x + rect.width && rect.y <= y && y <= rect.y + rect.height;
    }

    static containsWithPadding(rect: Rect, x: number, y: number, paddingLeftRight: number, paddingTopBottom: number): boolean {
        return rect.x + paddingLeftRight <= x
            && x <= rect.x + rect.width - paddingLeftRight
            && rect.y + paddingTopBottom <= y
            && y <= rect.y + rect.height - paddingTopBottom;
    }

    static containsWithMargin(rect: Rect, x: number, y: number, t: number, r: number, b: number, l: number): boolean {
        return rect.x - l <= x
            && x <= rect.x + rect.width + r
            && rect.y - t <= y
            && y <= rect.y + rect.height + b;
    }

    static intersect(r1: Rect, rect: Rect): boolean {
        let maxX = r1.x + r1.width >= rect.x + rect.width ? r1.x + r1.width : rect.x + rect.width;
        let maxY = r1.y + r1.height >= rect.y + rect.height ? r1.y + r1.height : rect.y + rect.height;
        let minX = r1.x <= rect.x ? r1.x : rect.x;
        let minY = r1.y <= rect.y ? r1.y : rect.y;
        if (maxX - minX <= rect.width + r1.width && maxY - minY <= r1.height + rect.height) {
            return true;
        } else {
            return false;
        }
    }

    contains(x: number, y: number): boolean {
        return this.x <= x && x <= this.x + this.width && this.y <= y && y <= this.y + this.height;
    }

    containsWithPadding(x: number, y: number, paddingLeftRight: number, paddingTopBottom: number): boolean {
        return this.x + paddingLeftRight <= x
            && x <= this.x + this.width - paddingLeftRight
            && this.y + paddingTopBottom <= y
            && y <= this.y + this.height - paddingTopBottom;
    }

    containsWithMargin(x: number, y: number, t: number, r: number, b: number, l: number): boolean {
        return this.x - l <= x
            && x <= this.x + this.width + r
            && this.y - t <= y
            && y <= this.y + this.height + b;
    }

    /**
     * 判断是否相交
     * @param rect
     */
    intersect(rect: Rect): boolean {
        let maxX = this.x + this.width >= rect.x + rect.width ? this.x + this.width : rect.x + rect.width;
        let maxY = this.y + this.height >= rect.y + rect.height ? this.y + this.height : rect.y + rect.height;
        let minX = this.x <= rect.x ? this.x : rect.x;
        let minY = this.y <= rect.y ? this.y : rect.y;
        if (maxX - minX <= rect.width + this.width && maxY - minY <= this.height + rect.height) {
            return true;
        } else {
            return false;
        }
    }
}

export class Point {
    x: number = 0
    y: number = 0

    constructor(x: number, y: number) {
        this.x = x;
        this.y = y;
    }
}

export class BaseStruct {
    frame: Rect | undefined
    isHover: boolean = false;
}

export function drawLines(ctx: CanvasRenderingContext2D, xs: Array<any>, height: number, lineColor: string) {
    if (ctx) {
        ctx.lineWidth = 1;
        ctx.strokeStyle = lineColor || "#dadada";
        xs?.forEach(it => {
            ctx.moveTo(Math.floor(it), 0)
            ctx.lineTo(Math.floor(it), height)
        })
        ctx.stroke();
    }
}

export function drawFlagLine(ctx: any, hoverFlag: any, selectFlag: any, startNS: number, endNS: number, totalNS: number, frame: any, slicesTime: { startTime: number | null, endTime: number | null, color: string | null } | undefined) {
    if (ctx) {
        if (hoverFlag) {
            ctx.beginPath();
            ctx.lineWidth = 2;
            ctx.strokeStyle = hoverFlag?.color || "#dadada";
            ctx.moveTo(Math.floor(hoverFlag.x), 0)
            ctx.lineTo(Math.floor(hoverFlag.x), frame.height)
            ctx.stroke();
            ctx.closePath();
        }
        if (selectFlag) {
            ctx.beginPath();
            ctx.lineWidth = 2;
            ctx.strokeStyle = selectFlag?.color || "#dadada";
            selectFlag.x = ns2x(selectFlag.time, startNS, endNS, totalNS, frame);
            ctx.moveTo(Math.floor(selectFlag.x), 0)
            ctx.lineTo(Math.floor(selectFlag.x), frame.height)
            ctx.stroke();
            ctx.closePath();
        }
        if (slicesTime && slicesTime.startTime && slicesTime.endTime) {
            ctx.beginPath();
            ctx.lineWidth = 1;
            ctx.strokeStyle = slicesTime.color || "#dadada";
            let x1 = ns2x(slicesTime.startTime, startNS, endNS, totalNS, frame);
            let x2 = ns2x(slicesTime.endTime, startNS, endNS, totalNS, frame);
            ctx.moveTo(Math.floor(x1), 0)
            ctx.lineTo(Math.floor(x1), frame.height)
            ctx.moveTo(Math.floor(x2), 0)
            ctx.lineTo(Math.floor(x2), frame.height)
            ctx.stroke();
            ctx.closePath();
        }
    }
}

export function drawSelection(context: any, params: any) {
    if (params.isRangeSelect && params.rangeSelectObject) {
        params.rangeSelectObject!.startX = Math.floor(ns2x(params.rangeSelectObject!.startNS!, params.startNS, params.endNS, params.totalNS, params.frame));
        params.rangeSelectObject!.endX = Math.floor(ns2x(params.rangeSelectObject!.endNS!, params.startNS, params.endNS, params.totalNS, params.frame));
        if (context) {
            context.globalAlpha = 0.5
            context.fillStyle = "#666666"
            context.fillRect(params.rangeSelectObject!.startX!, params.frame.y, params.rangeSelectObject!.endX! - params.rangeSelectObject!.startX!, params.frame.height)
            context.globalAlpha = 1
        }
    }
}

export function drawWakeUp(context: CanvasRenderingContext2D | any, wake: WakeupBean | undefined | null, startNS: number, endNS: number, totalNS: number, frame: Rect, selectCpuStruct: CpuStruct | undefined = undefined, currentCpu: number | undefined = undefined) {
    if (wake) {
        let x1 = Math.floor(ns2x((wake.wakeupTime || 0), startNS, endNS, totalNS, frame));
        context.beginPath();
        context.lineWidth = 2;
        context.fillStyle = "#000000";
        if (x1 > 0 && x1 < frame.x + frame.width) {
            context.moveTo(x1, frame.y);
            context.lineTo(x1, frame.y + frame.height);
            if (currentCpu == wake.cpu) {
                let centerY = Math.floor(frame.y + frame.height / 2);
                context.moveTo(x1, centerY - 6);
                context.lineTo(x1 + 4, centerY);
                context.lineTo(x1, centerY + 6);
                context.lineTo(x1 - 4, centerY);
                context.lineTo(x1, centerY - 6);
                context.fill();
            }
        }
        if (selectCpuStruct) {
            let x2 = Math.floor(ns2x((selectCpuStruct.startTime || 0), startNS, endNS, totalNS, frame));
            let y = frame.y + frame.height - 10;
            context.moveTo(x1, y);
            context.lineTo(x2, y);

            let s = ns2s((selectCpuStruct.startTime || 0) - (wake.wakeupTime || 0));
            let distance = x2 - x1;
            if (distance > 12) {
                context.moveTo(x1, y);
                context.lineTo(x1 + 6, y - 3);
                context.moveTo(x1, y);
                context.lineTo(x1 + 6, y + 3);
                context.moveTo(x2, y);
                context.lineTo(x2 - 6, y - 3);
                context.moveTo(x2, y);
                context.lineTo(x2 - 6, y + 3);
                let measure = context.measureText(s);
                let tHeight = measure.actualBoundingBoxAscent + measure.actualBoundingBoxDescent
                let xStart = x1 + Math.floor(distance / 2 - measure.width / 2);
                if (distance > measure.width + 4) {
                    context.fillStyle = "#ffffff"
                    context.fillRect(xStart - 2, y - 4 - tHeight, measure.width + 4, tHeight + 4);
                    context.font = "10px solid";
                    context.fillStyle = "#000000";
                    context.textBaseline = "bottom";
                    context.fillText(s, xStart, y - 2);
                }

            }
        }
        context.strokeStyle = "#000000";
        context.stroke();
        context.closePath();
    }
}

export function drawLoading(ctx: CanvasRenderingContext2D, startNS: number, endNS: number, totalNS: number, frame: any, left: number, right: number) {
}
