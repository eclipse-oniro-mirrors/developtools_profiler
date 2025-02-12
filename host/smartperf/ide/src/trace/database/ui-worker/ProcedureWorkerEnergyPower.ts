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

export class EnergyPowerRender extends Render {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            power(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache
                || !req.range.refresh, req.params.maxPowerName);
        } else {
            if (!req.useCache) {
                power(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false, req.params.maxPowerName);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.canvas.width, EnergyPowerStruct.rowHeight);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS,
                    arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            req.context.beginPath();
            EnergyPowerStruct.hoverEnergyPowerStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        EnergyPowerStruct.hoverEnergyPowerStruct = re;
                        break;
                    }
                }
            }
            EnergyPowerStruct.selectEnergyPowerStruct = req.params.selectEnergyPowerStruct;
            for (let index = 0; index < filter.length; index++) {
                EnergyPowerStruct.draw(req, index, filter[index])
            }
            req.context.stroke();
            drawSelection(req.context, req.params);
            req.context.closePath();
            if (EnergyPowerStruct.maxPower != 0) {
                let s = EnergyPowerStruct.maxPower.toString()
                let textMetrics = req.context.measureText(s);
                req.context.globalAlpha = 1.0
                req.context.fillStyle = "#f0f0f0"
                req.context.fillRect(0, 5, textMetrics.width + 8, 18)
                req.context.globalAlpha = 1
                req.context.fillStyle = "#333"
                req.context.textBaseline = "middle"
                req.context.fillText(s, 4, 5 + 9)
            }
            drawLegend(req)
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS,
                req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: EnergyPowerStruct.hoverEnergyPowerStruct
        });
    }
}

export function drawLegend(req: RequestMessage){
    let textList = ["CPU", "LOCATION", "GPU", "DISPLAY", "CAMERA", "BLUETOOTH", "FLASHLIGHT", "AUDIO", "WIFISCAN"]
    for (let index = 0; index < textList.length; index++) {
        let text = req.context.measureText(textList[index]);
        req.context.fillStyle = EnergyPowerStruct.getHistogramColor(textList[index]);
        req.context.globalAlpha = 1
        if(index == 0){
            req!.context.fillRect(req.canvas.width - (EnergyPowerStruct.powerItemNumber * 80), 12, 8, 8);
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText(textList[index], req.canvas.width - (EnergyPowerStruct.powerItemNumber * 80) + 10, 18)
            EnergyPowerStruct.currentTextWidth = req.canvas.width - (EnergyPowerStruct.powerItemNumber * 80) + 40 + text.width
        } else {
            req!.context.fillRect(EnergyPowerStruct.currentTextWidth, 12, 8, 8);
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req!.context.fillText(textList[index], EnergyPowerStruct.currentTextWidth + 12, 18);
            EnergyPowerStruct.currentTextWidth = EnergyPowerStruct.currentTextWidth + 40 + text.width
        }
    }
}

export function power(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number,
                      frame: any, use: boolean, appName: string) {
    if (use && res.length > 0) {
        for (let i = 0; i < res.length; i++) {
            let item = res[i];
            let obj = item[appName]
            if (obj != undefined) {
                if ((obj.ts + 1000000000) > (startNS || 0) && (obj.ts || 0) < (endNS || 0)) {
                    EnergyPowerStruct.setPowerFrame(item, 5, startNS || 0, endNS || 0,
                        totalNS || 0, frame)
                } else {
                    obj.frame = null;
                }
            }
        }
        return;
    }
    res.length = 0;
    if (list) {
        let firstList: Array<any> = []
        EnergyPowerStruct.maxPower = 0
        for (let index = 0; index < list.length; index++) {
            let item = list[index];
            let obj = item[appName]
            if (obj != undefined) {
                if ((obj.ts + 1000000000) > (startNS || 0) && (obj.ts || 0) < (endNS || 0)) {
                    firstList.push(obj)
                }
            }
        }

        let array = firstList.sort((a, b) => a.ts - b.ts);
        for (let index = 0; index < array.length; index++) {
            if (res.length == 0) {
                res.push(array[index])
            } else {
                let rightTime = array[index].ts + 500000000;
                let leftTime = array[index].ts - 500000000;
                let obj = res[res.length - 1];
                if (obj.ts >= leftTime && obj.ts <= rightTime) {
                    obj.cpu = obj.cpu == 0 ? array[index].cpu : obj.cpu
                    obj.location = obj.location == 0 ? array[index].location : obj.location
                    obj.gpu = obj.gpu == 0 ? array[index].gpu : obj.gpu
                    obj.display = obj.display == 0 ? array[index].display : obj.display
                    obj.camera = obj.camera == 0 ? array[index].camera : obj.camera
                    obj.bluetooth = obj.bluetooth == 0 ? array[index].bluetooth : obj.bluetooth
                    obj.flashlight = obj.flashlight == 0 ? array[index].flashlight : obj.flashlight
                    obj.audio = obj.audio ? array[index].audio : obj.audio
                    obj.wifiscan = obj.wifiscan == 0 ? array[index].wifiscan : obj.wifiscan
                } else {
                    res.push(array[index])
                }
            }
        }
        res.forEach(item => {
            EnergyPowerStruct.setPowerFrame(item, 5, startNS || 0, endNS || 0,
                totalNS || 0, frame)
            let max = (item.cpu || 0) + (item.location || 0) + (item.gpu || 0) + (item.display || 0) + (item.camera
                || 0) + (item.bluetooth || 0) + (item.flashlight || 0) + (item.audio || 0) + (item.wifiscan || 0)
            if (max > EnergyPowerStruct.maxPower) {
                EnergyPowerStruct.maxPower = max
            }
        })
    }
}

export class EnergyPowerStruct extends BaseStruct {
    static maxPower: number = 0
    static maxPowerName: string = "0"
    static powerItemNumber: number = 9
    static currentTextWidth: number = 0
    static rowHeight: number = 200
    static appName: string | undefined
    static hoverEnergyPowerStruct: EnergyPowerStruct | undefined;
    static selectEnergyPowerStruct: EnergyPowerStruct | undefined;
    name: string | undefined
    ts: number = 0
    cpu: number = 0
    location: number = 0
    gpu: number = 0
    display: number = 0
    camera: number = 0
    bluetooth: number = 0
    flashlight: number = 0
    audio: number = 0
    wifiscan: number = 0

    static draw(req: RequestMessage, index: number, data: EnergyPowerStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            req!.context.globalAlpha = 1.0;
            req!.context.lineWidth = 1;
            this.currentTextWidth = 0
            let cpuHeight = this.drawHistogram(req, data, -1, data.cpu!, "CPU");
            let locationHeight = this.drawHistogram(req, data, cpuHeight, data.location!, "LOCATION");
            let gpuHeight = this.drawHistogram(req, data, cpuHeight - locationHeight, data.gpu!,
                "GPU");
            let displayHeight = this.drawHistogram(req, data,
                cpuHeight - locationHeight - gpuHeight, data.display!, "DISPLAY");
            let cameraHeight = this.drawHistogram(req, data, cpuHeight - locationHeight - gpuHeight -
                displayHeight, data.camera!, "CAMERA");
            let bluetoothHeight = this.drawHistogram(req, data, cpuHeight - locationHeight - gpuHeight -
                displayHeight - cameraHeight, data.bluetooth!, "BLUETOOTH");
            let flashlightHeight = this.drawHistogram(req, data, cpuHeight - locationHeight - gpuHeight -
                displayHeight - cameraHeight - bluetoothHeight, data.flashlight!, "FLASHLIGHT");
            let audioHeight = this.drawHistogram(req, data, cpuHeight - locationHeight - gpuHeight -
                displayHeight - cameraHeight - bluetoothHeight - flashlightHeight, data.audio!,
                "AUDIO");
            let wifiHeight = this.drawHistogram(req, data, cpuHeight - locationHeight - gpuHeight -
                displayHeight - cameraHeight - bluetoothHeight - flashlightHeight - audioHeight, data.wifiscan!,
                "WIFISCAN");
            let maxPointY = this.drawPolyline(req, index, data)
            if (data.ts === EnergyPowerStruct.hoverEnergyPowerStruct?.ts) {
                req.context.globalAlpha = 1
                req!.context.lineWidth = 2;
                req.context.fillStyle = "#333"
                req!.context.strokeRect(data.frame!.x, maxPointY, data.frame!.width, req.canvas.width - maxPointY);
            }
        }
        req!.context.globalAlpha = 1.0;
        req!.context.lineWidth = 1;
    }

    static drawHistogram(req: RequestMessage, data: EnergyPowerStruct, height: number, itemValue: number,
                         textItem: string): number {
        let histogramColor = this.getHistogramColor(textItem);
        req!.context.fillStyle = histogramColor;
        req!.context.strokeStyle = histogramColor;
        let dataHeight: number = Math.floor(((itemValue || 0) * (this.rowHeight - 40)) /
            EnergyPowerStruct.maxPower);
        let drawStartY = 0;

        if (height == -1) {
            drawStartY = data.frame!.y + this.rowHeight - dataHeight + 4;
            req!.context.fillRect(data.frame!.x, drawStartY, data.frame!.width, dataHeight);
            return drawStartY;
        } else {
            drawStartY = height - dataHeight;
            req!.context.fillRect(data.frame!.x, drawStartY, data.frame!.width, dataHeight);
            return dataHeight;
        }
    }

    static drawPolyline(req: RequestMessage, index: number, data: EnergyPowerStruct) {
        let pointX = ns2x(((data.ts || 0) + 500000000), req.startNS, req.endNS, req.totalNS, req.frame);
        let maxHeight = (data.cpu || 0) + (data.location || 0) + (data.gpu || 0) + (data.display || 0) + (data.camera
            || 0) + (data.bluetooth || 0) + (data.flashlight || 0) + (data.audio || 0) + (data.wifiscan || 0)
        let drawHeight: number = Math.floor(((maxHeight || 0) * (this.rowHeight - 40)) /
            EnergyPowerStruct.maxPower);
        let drawY = data.frame!.y + this.rowHeight - drawHeight + 5
        req!.context.fillStyle = "#ED6F21";
        req!.context.strokeStyle = "#ED6F21";

        if (index == 0) {
            req.context.beginPath()
            req.context.arc(pointX, drawY, 4, 0, 2 * Math.PI)
            req.context.fill()
            req.context.moveTo(pointX, drawY)
        } else {
            req.context.lineTo(pointX, drawY);
            req.context.stroke();
            req.context.beginPath()
            req.context.arc(pointX, drawY, 4, 0, 2 * Math.PI)
            req.context.fill()
        }
        return drawY
    }

    static setPowerFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let startPointX: number
        let endPointX: number
        if ((node.ts || 0) < startNS) {
            startPointX = 0
        } else {
            startPointX = ns2x((node.ts || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.ts + 1000000000) > endNS) {
            endPointX = frame.width;
        } else {
            endPointX = ns2x((node.ts + 1000000000), startNS, endNS, totalNS, frame);
        }
        let frameWidth = endPointX - startPointX <= 1 ? 1 : endPointX - startPointX;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.floor(startPointX);
        node.frame.y = frame.y + padding;
        node.frame.width = Math.ceil(frameWidth);
        node.frame.height = Math.floor(frame.height - padding * 2);
    }

    static getHistogramColor(textItem: string): string {
        switch (textItem) {
            case 'CPU':
                return "#92D6CC";
            case 'LOCATION':
                return "#61CFBE"
            case 'GPU':
                return "#86C5E3"
            case 'DISPLAY':
                return "#46B1E3"
            case 'CAMERA':
                return "#C386F0"
            case 'BLUETOOTH':
                return "#8981F7"
            case 'AUDIO':
                return "#AC49F5"
            case 'WIFISCAN':
                return "#92C4BD"
            default:
                return "#564AF7"
        }
    }
}
