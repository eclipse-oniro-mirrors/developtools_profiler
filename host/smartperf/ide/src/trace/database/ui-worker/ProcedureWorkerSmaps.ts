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
    drawSelection,
    ns2x,
    Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class SmapsRender extends Render {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            smaps(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                smaps(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            req.context.beginPath();
            let maxValue = 0;
            let maxValueName = "";
            if (req.params.maxValue != undefined || req.params.maxValueName != undefined) {
                maxValue = req.params.maxValue;
                maxValueName = req.params.maxValueName;
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            SmapsStruct.hoverSmapsStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        SmapsStruct.hoverSmapsStruct = re;
                        break;
                    }
                }
            }
            let drawColor = "#0A59F7"
            if (req.params.rowName != undefined) {
                switch (req.params.rowName) {
                    case "dirty":
                        drawColor = "#0A59F7";
                        break;
                    case "swapper":
                        drawColor = "#46B1E3";
                        break;
                     case "resident_size":
                        drawColor = "#564AF7";
                        break;
                }
            }
            SmapsStruct.selectSmapsStruct = req.params.selectSmapsStruct;
            for (let re of filter) {
                SmapsStruct.draw(req.context, re, maxValue, drawColor)
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: SmapsStruct.hoverSmapsStruct
        });
    }
}

export function smaps(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
    if (use && res.length > 0) {
        for (let i = 0; i < res.length; i++) {
            let item = res[i];
            if ((item.startNS || 0) + (item.dur || 0) > (startNS || 0) && (item.startNS || 0) < (endNS || 0)) {
                SmapsStruct.setSmapsFrame(item, 5, startNS || 0, endNS || 0, totalNS || 0, frame)
            } else {
                item.frame = null;
            }
        }
        return;
    }
    res.length = 0;
    if (list) {
        for (let index = 0; index < list.length; index++) {
            let item = list[index];
            if (index === list.length - 1) {
                item.dur = (endNS || 0) - (item.startNS || 0)
            } else {
                item.dur = (list[index + 1].startNS || 0) - (item.startNS || 0)
            }
            if ((item.startNS || 0) + (item.dur || 0) > (startNS || 0) && (item.startNS || 0) < (endNS || 0)) {
                SmapsStruct.setSmapsFrame(list[index], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                if (index > 0 && ((list[index - 1].frame?.x || 0) == (list[index].frame?.x || 0) && (list[index - 1].frame?.width || 0) == (list[index].frame?.width || 0))) {

                } else {
                    res.push(item)
                }
            }
        }
    }
}

export class SmapsStruct extends BaseStruct {
    static maxValue: number = 0
    static maxValueName: string = "0 KB/S"
    static hoverSmapsStruct: SmapsStruct | undefined;
    static selectSmapsStruct: SmapsStruct | undefined;
    value: number | undefined
    startNS: number | undefined
    dur: number | undefined

    static draw(context2D: CanvasRenderingContext2D, data: SmapsStruct, maxValue: number, drawColor: string) {
        if (data.frame) {
            let width = data.frame.width || 0;
            context2D.fillStyle = drawColor
            context2D.strokeStyle = drawColor
            if (data.startNS === SmapsStruct.hoverSmapsStruct?.startNS) {
                context2D.lineWidth = 1;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / maxValue);
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
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0)) / maxValue);
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight + 4, width, drawHeight)
            }
        }
        context2D.globalAlpha = 1.0;
        context2D.lineWidth = 1;
    }

    static setSmapsFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let startPointX: number, endPointX: number

        if ((node.startNS || 0) < startNS) {
            startPointX = 0
        } else {
            startPointX = ns2x((node.startNS || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startNS || 0) + (node.dur || 0) > endNS) {
            endPointX = frame.width;
        } else {
            endPointX = ns2x((node.startNS || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
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