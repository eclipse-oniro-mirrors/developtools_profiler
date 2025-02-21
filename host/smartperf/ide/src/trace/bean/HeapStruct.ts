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

import {BaseStruct} from "./BaseStruct.js";
import {ns2x} from "../component/trace/TimerShaftElement.js";
import {Rect} from "../component/trace/timer-shaft/Rect.js";

export class HeapStruct extends BaseStruct {
    static hoverHeapStruct: HeapStruct | undefined;
    startTime: number | undefined
    endTime: number | undefined
    dur: number | undefined
    eventType: string | undefined
    heapsize: number | undefined
    maxHeapSize: number = 0
    minHeapSize: number = 0

    static setFrame(node: HeapStruct, padding: number, startNS: number, endNS: number, totalNS: number, frame: Rect) {
        let x1: number, x2: number;
        if ((node.startTime || 0) < startNS) {
            x1 = 0;
        } else {
            x1 = ns2x((node.startTime || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startTime || 0) + (node.dur || 0) > endNS) {
            x2 = frame.width;
        } else {
            // @ts-ignore
            x2 = ns2x(node.startTime + node.dur, startNS, endNS, totalNS, frame);
        }
        let getV: number = x2 - x1 <= 1 ? 1 : x2 - x1;
        let rectangle: Rect = new Rect(Math.floor(x1), Math.ceil(frame.y + padding), Math.ceil(getV), Math.floor(frame.height - padding * 2));
        node.frame = rectangle;
    }

    static draw(ctx: CanvasRenderingContext2D, data: HeapStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            ctx.fillStyle = "#2db3aa"
            ctx.strokeStyle = "#2db3aa"
            if (data.startTime === HeapStruct.hoverHeapStruct?.startTime) {
                ctx.lineWidth = 1;
                ctx.globalAlpha = 0.6;
                let drawHeight: number = Math.ceil(((data.heapsize || 0) * (data.frame.height || 0)) / data.maxHeapSize);
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
                let drawHeight: number = Math.ceil(((data.heapsize || 0) * (data.frame.height || 0)) / data.maxHeapSize);
                ctx.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
            }
        }
        ctx.globalAlpha = 1.0;
        ctx.lineWidth = 1;
    }
}