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
    BaseStruct,
    drawFlagLine,
    drawLines,
    drawLoading,
    drawSelection,
    drawWakeUp,
    ns2x,
    Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class SdkCounterRender extends Render {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            this.counter(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                this.counter(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            req.context.beginPath();
            let maxCounter = req.params.maxCounter;
            let maxCounterName = req.params.maxCounterName;
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            CounterStruct.hoverCounterStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        CounterStruct.hoverCounterStruct = re;
                        break;
                    }
                }
            }
            CounterStruct.selectCounterStruct = req.params.selectCounterStruct;
            for (let re of filter) {
                CounterStruct.draw(req.context, re, maxCounter)
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            let textMetrics = req.context.measureText(maxCounterName);
            req.context.globalAlpha = 0.8
            req.context.fillStyle = "#f0f0f0"
            req.context.fillRect(0, 5, textMetrics.width + 8, 18)
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText(maxCounterName, 4, 5 + 9)
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame);
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: CounterStruct.hoverCounterStruct
        });
    }

    counter(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
        if (use && res.length > 0) {
            for (let index = 0; index < res.length; index++) {
                let item = res[index];
                if ((item.ts || 0) + (item.dur || 0) > (startNS || 0) && (item.ts || 0) < (endNS || 0)) {
                    CounterStruct.setCounterFrame(res[index], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                } else {
                    res[index].frame = null;
                }
            }
            return;
        }
        res.length = 0;
        if (list) {
            for (let index = 0; index < list.length; index++) {
                let item = list[index];
                if (index === list.length - 1) {
                    item.dur = (endNS || 0) - (item.ts || 0)
                } else {
                    item.dur = (list[index + 1].ts || 0) - (item.ts || 0)
                }
                if ((item.ts || 0) + (item.dur || 0) > (startNS || 0) && (item.ts || 0) < (endNS || 0)) {
                    CounterStruct.setCounterFrame(list[index], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                    if (index > 0 && ((list[index - 1].frame?.x || 0) == (list[index].frame?.x || 0) && (list[index - 1].frame?.width || 0) == (list[index].frame?.width || 0))) {

                    } else {
                        res.push(item)
                    }
                }
            }
        }
    }
}


export class CounterStruct extends BaseStruct {
    static maxCounter: number = 0
    static maxCounterName: string = ""
    static hoverCounterStruct: CounterStruct | undefined;
    static selectCounterStruct: CounterStruct | undefined;

    value: number | undefined
    ts: number | undefined
    counter_id: number | undefined


    static draw(context2D: CanvasRenderingContext2D, data: CounterStruct, maxCounter: number) {
        if (data.frame) {
            let width = data.frame.width || 0;
            context2D.fillStyle = "#67B0FC"
            context2D.strokeStyle = "#67B0FC"
            if (data.ts === CounterStruct.hoverCounterStruct?.ts) {
                context2D.lineWidth = 1;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / maxCounter);
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight + 4, width, drawHeight)
                context2D.beginPath()
                context2D.arc(data.frame.x, data.frame.y + data.frame.height - drawHeight + 4, 3, 0, 2 * Math.PI, true)
                context2D.fill()
                context2D.globalAlpha = 1.0;
                context2D.stroke();
                context2D.beginPath()
                context2D.moveTo(data.frame.x + 3, data.frame.y + data.frame.height - drawHeight + 4);
                context2D.lineWidth = 3;
                context2D.lineTo(data.frame.x + width, data.frame.y + data.frame.height - drawHeight + 4)
                context2D.stroke();
            } else {
                context2D.lineWidth = 1;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0)) / maxCounter);
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight + 4, width, drawHeight)
            }
        }
        context2D.globalAlpha = 1.0;
        context2D.lineWidth = 1;
    }

    static setCounterFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let startPointX: number, endPointX: number

        if ((node.ts || 0) < startNS) {
            startPointX = 0
        } else {
            startPointX = ns2x((node.ts || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.ts || 0) + (node.dur || 0) > endNS) {
            endPointX = frame.width;
        } else {
            endPointX = ns2x((node.ts || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
        }
        let frameWidth: number = endPointX - startPointX <= 1 ? 1 : endPointX - startPointX;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.floor(startPointX);
        node.frame.y = frame.y + padding;
        node.frame.width = Math.ceil(frameWidth);
        node.frame.height = Math.floor(frame.height - padding * 2);
    }
}
