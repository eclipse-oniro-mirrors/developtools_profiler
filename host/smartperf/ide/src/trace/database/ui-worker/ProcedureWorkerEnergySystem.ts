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
    drawFlagLine, drawLines,
    drawLoading,
    drawSelection,
    ns2x,
    Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class EnergySystemRender extends Render {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            system(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                system(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.canvas.width, req.canvas.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            req.context.beginPath();
            EnergySystemStruct.hoverEnergySystemStruct = undefined;
            if (req.isHover) {
                let resultList: any[] = []
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width) {
                        EnergySystemStruct.hoverEnergySystemStruct = re;
                        if (resultList.indexOf(re.type) === -1) {
                            resultList.push(re.type)
                        }
                    }
                }
                if (EnergySystemStruct.hoverEnergySystemStruct) {
                    if (resultList.indexOf(0) > -1) {
                        EnergySystemStruct.hoverEnergySystemStruct.workScheduler = "survive"
                    } else {
                        EnergySystemStruct.hoverEnergySystemStruct.workScheduler = "dead"
                    }
                    if (resultList.indexOf(1) > -1) {
                        EnergySystemStruct.hoverEnergySystemStruct.power = "survive"
                    } else {
                        EnergySystemStruct.hoverEnergySystemStruct.power = "dead"
                    }
                    if (resultList.indexOf(2) > -1) {
                        EnergySystemStruct.hoverEnergySystemStruct.location = "survive"
                    } else {
                        EnergySystemStruct.hoverEnergySystemStruct.location = "dead"
                    }
                }
            }
            EnergySystemStruct.selectEnergySystemStruct = req.params.selectEnergySystemStruct;
            for (let re of filter) {
                EnergySystemStruct.draw(req.context, re)
            }
            drawLegend(req);
            drawSelection(req.context, req.params);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: EnergySystemStruct.hoverEnergySystemStruct
        });
    }
}

export function drawLegend(req: RequestMessage) {
    let textList = ["WORKSCHEDULER", "POWER_RUNNINGLOCK", "LOCATION"]
    for (let index = 0; index < textList.length; index++) {
        let text = req.context.measureText(textList[index]);
        req.context.fillStyle = EnergySystemStruct.getColor(index);
        if (textList[index] == "WORKSCHEDULER") {
            req.context.fillRect(req.context.canvas.width - (EnergySystemStruct.itemNumber * 120), 12, 8, 8);
            req.context.globalAlpha = 1
            req.context.textBaseline = "middle"
            req.context.fillStyle = "#333"
            req.context.fillText(textList[index], req.context.canvas.width - (EnergySystemStruct.itemNumber * 120) + 10, 18)
            EnergySystemStruct.currentTextWidth = req.context.canvas.width - (EnergySystemStruct.itemNumber * 120) + 40 + text.width
        } else {
            req.context.fillRect(EnergySystemStruct.currentTextWidth, 12, 8, 8);
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText(textList[index], EnergySystemStruct.currentTextWidth + 12, 18);
            EnergySystemStruct.currentTextWidth = EnergySystemStruct.currentTextWidth + 40 + text.width
        }
    }
}

export function system(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
    if (use && res.length > 0) {
        for (let i = 0; i < res.length; i++) {
            let item = res[i];
            if ((item.startNs || 0) + (item.dur || 0) > (startNS || 0) && (item.startNs || 0) < (endNS || 0)) {
                EnergySystemStruct.setSystemFrame(item, 10, startNS || 0, endNS || 0, totalNS || 0, frame)
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
            if ((item.startNs || 0) + (item.dur || 0) > (startNS || 0) && (item.startNs || 0) < (endNS || 0)) {
                EnergySystemStruct.setSystemFrame(list[index], 10, startNS || 0, endNS || 0, totalNS || 0, frame)
                res.push(item)
            }
        }
    }
}

export class EnergySystemStruct extends BaseStruct {
    static hoverEnergySystemStruct: EnergySystemStruct | undefined;
    static selectEnergySystemStruct: EnergySystemStruct | undefined;
    static itemNumber: number = 3
    static currentTextWidth: number = 0
    type: number | undefined
    startNs: number | undefined
    dur: number | undefined
    workScheduler: string | undefined
    power: string | undefined
    location: string | undefined

    static draw(context2D: CanvasRenderingContext2D, data: EnergySystemStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            context2D.globalAlpha = 1.0;
            context2D.lineWidth = 1;
            context2D.fillStyle = this.getColor(data.type!);
            context2D.strokeStyle = this.getColor(data.type!);
            context2D.fillRect(data.frame.x, data.frame.y + 4, width, data.frame.height)
        }
        context2D.globalAlpha = 1.0;
        context2D.lineWidth = 1;
    }

    static setSystemFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let startPointX: number;
        let endPointX: number;
        if ((node.startNs || 0) < startNS) {
            startPointX = 0
        } else {
            startPointX = ns2x((node.startNs || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startNs || 0) + (node.dur || 0) > endNS) {
            endPointX = frame.width;
        } else {
            endPointX = ns2x((node.startNs || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
        }
        let frameWidth: number = endPointX - startPointX <= 1 ? 1 : endPointX - startPointX;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.floor(startPointX);
        if (node.type === 0) {
            node.frame.y = frame.y + padding * 2.5;
        } else if (node.type === 1) {
            node.frame.y = frame.y + (padding * 4.5);
        } else if (node.type === 2) {
            node.frame.y = frame.y + (padding * 6.5);
        }
        node.frame.width = Math.ceil(frameWidth);
        node.frame.height = Math.floor(padding);
    }

    static getColor(textItem: number): string {
        switch (textItem) {
            case 0:
                return "#E64566";
            case 1:
                return "#FFC880";
            default:
                return "#564AF7";
        }
    }
}
