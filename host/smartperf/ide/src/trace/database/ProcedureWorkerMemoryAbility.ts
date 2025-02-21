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

import {BaseStruct, ColorUtils, ns2x} from "./ProcedureWorkerCommon.js";

export function memoryAbility(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
    if (use && res.length > 0) {
        for (let i = 0; i < res.length; i++) {
            let item = res[i];
            if ((item.startNS || 0) + (item.dur || 0) > (startNS || 0) && (item.startNS || 0) < (endNS || 0)) {
                MemoryAbilityMonitorStruct.setMemoryFrame(item, 5, startNS || 0, endNS || 0, totalNS || 0, frame)
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
                MemoryAbilityMonitorStruct.setMemoryFrame(list[index], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                if (index > 0 && ((list[index - 1].frame?.x || 0) == (list[index].frame?.x || 0) && (list[index - 1].frame?.width || 0) == (list[index].frame?.width || 0))) {

                } else {
                    res.push(item)
                }
            }
        }
    }
}

export class MemoryAbilityMonitorStruct extends BaseStruct {
    static maxMemoryByte: number = 0
    static maxMemoryByteName: string = "0 MB"
    static hoverMemoryAbilityStruct: MemoryAbilityMonitorStruct | undefined;
    static selectMemoryAbilityStruct: MemoryAbilityMonitorStruct | undefined;
    cpu: number | undefined
    value: number | undefined
    startNS: number | undefined
    dur: number | undefined

    static draw(context2D: CanvasRenderingContext2D, data: MemoryAbilityMonitorStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            let index = 2;
            context2D.fillStyle = ColorUtils.colorForTid(index)
            context2D.strokeStyle = ColorUtils.colorForTid(index)
            if (data.startNS === MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct?.startNS) {
                context2D.lineWidth = 1;
                context2D.globalAlpha = 0.6;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / MemoryAbilityMonitorStruct.maxMemoryByte);
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
                context2D.globalAlpha = 0.6;
                context2D.lineWidth = 1;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0)) / MemoryAbilityMonitorStruct.maxMemoryByte);
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight + 4, width, drawHeight)
            }
        }
        context2D.globalAlpha = 1.0;
        context2D.lineWidth = 1;
    }

    static setMemoryFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
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

const textPadding = 2;
