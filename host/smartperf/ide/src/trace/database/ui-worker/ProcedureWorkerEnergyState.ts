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
    ns2x,
    Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class EnergyStateRender extends Render {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            state(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                state(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.canvas.width, req.canvas.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS,
                    arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            req.context.beginPath();
            EnergyStateStruct.maxState = req.params.maxState;
            EnergyStateStruct.maxStateName = req.params.maxStateName;
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            EnergyStateStruct.hoverEnergyStateStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        EnergyStateStruct.hoverEnergyStateStruct = re;
                        break;
                    }
                }
            }
            EnergyStateStruct.selectEnergyStateStruct = req.params.selectEnergyStateStruct;
            for (let re of filter) {
                EnergyStateStruct.draw(req.context, re)
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            if (EnergyStateStruct.maxStateName != "enable" && EnergyStateStruct.maxStateName != "disable") {
                let s = EnergyStateStruct.maxStateName
                let textMetrics = req.context.measureText(s);
                req.context.globalAlpha = 1.0
                req.context.fillStyle = "#f0f0f0"
                req.context.fillRect(0, 5, textMetrics.width + 8, 18)
                req.context.fillStyle = "#333"
                req.context.textBaseline = "middle"
                req.context.fillText(s, 4, 5 + 9)
            }
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS,
                req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: EnergyStateStruct.hoverEnergyStateStruct
        });
    }
}

export function state(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number,
                      frame: any, use: boolean) {
    if (use && res.length > 0) {
        for (let i = 0; i < res.length; i++) {
            let item = res[i];
            if ((item.startNs || 0) + (item.dur || 0) > (startNS || 0) && (item.startNs || 0) < (endNS || 0)) {
                EnergyStateStruct.setStateFrame(item, 5, startNS || 0, endNS || 0,
                    totalNS || 0, frame)
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
                item.dur = (endNS || 0) - (item.startNs || 0)
            } else {
                item.dur = (list[index + 1].startNs || 0) - (item.startNs || 0)
            }
            if ((item.startNs || 0) + (item.dur || 0) > (startNS || 0) && (item.startNs || 0) < (endNS || 0)) {
                EnergyStateStruct.setStateFrame(list[index], 5, startNS || 0, endNS || 0,
                    totalNS || 0, frame)
                if (index > 0 && ((list[index - 1].frame?.x || 0) == (list[index].frame?.x || 0) && (list[index - 1].frame?.width || 0) == (list[index].frame?.width || 0))) {

                } else {
                    res.push(item)
                }
            }
        }
    }
}

export class EnergyStateStruct extends BaseStruct {
    static maxState: number = 0
    static maxStateName: string = "0"
    static hoverEnergyStateStruct: EnergyStateStruct | undefined;
    static selectEnergyStateStruct: EnergyStateStruct | undefined;
    type: string | undefined
    value: number | undefined
    startNs: number | undefined
    dur: number | undefined

    sensorType: number | undefined
    pkg_name: string | undefined
    deviceState: number | undefined
    deviceType: number | undefined

    static draw(context2D: CanvasRenderingContext2D, data: EnergyStateStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            let drawColor = this.setDrawColor(data.type!);
            context2D.fillStyle = drawColor;
            context2D.strokeStyle = drawColor;
            context2D.globalAlpha = 1.0;
            context2D.lineWidth = 1;
            let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0)) / EnergyStateStruct.maxState);
            if (EnergyStateStruct.maxStateName === "enable" || EnergyStateStruct.maxStateName === "disable") {
                if (data.value == 0) {
                    drawHeight = data.frame.height;
                    context2D.fillRect(data.frame.x, data.frame.y + 4, width, data.frame.height)
                }
            } else {
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight + 4, width, drawHeight)
            }
            if (data.startNs === EnergyStateStruct.hoverEnergyStateStruct?.startNs) {
                let pointy = data.frame.y + data.frame.height + 4
                if (data.value == 0) {
                    pointy -= drawHeight
                }
                context2D.beginPath()
                context2D.arc(data.frame.x, pointy, 3, 0, 2 * Math.PI, true)
                context2D.fill()
                context2D.globalAlpha = 1.0;
                context2D.stroke();
                context2D.beginPath()
                context2D.moveTo(data.frame.x + 3, pointy);
                context2D.lineWidth = 3;
                context2D.lineTo(data.frame.x + width, pointy)
                context2D.stroke();
            }
        }
        context2D.globalAlpha = 1.0;
        context2D.lineWidth = 1;
    }

    static setStateFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let startPointX: number, endPointX: number

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
        node.frame.y = frame.y + padding;
        node.frame.width = Math.ceil(frameWidth);
        node.frame.height = Math.floor(frame.height - padding * 2);
    }

    static setDrawColor(eventType: string): string {
        switch (eventType) {
            case 'BRIGHTNESS_NIT':
                return "#92D6CC";
            case 'SIGNAL_LEVEL':
                return "#61CFBE"
            case 'WIFI_EVENT_RECEIVED':
                return "#46B1E3"
            case 'AUDIO_STREAM_CHANGE':
                return "#ED6F21"
            case 'WIFI_STATE':
                return "#61CFBE"
            case 'LOCATION_SWITCH_STATE':
                return "#61CFBE"
            case 'SENSOR_STATE':
                return "#61CFBE"
            default:
                return "#61CFBE"
        }
    }
}