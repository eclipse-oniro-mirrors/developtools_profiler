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

import { ColorUtils } from "../component/trace/base/ColorUtils.js";
import {BaseStruct} from "./BaseStruct.js";

export class MemoryAbilityMonitorStruct extends BaseStruct {
    static maxMemoryByte: number = 0
    static maxMemoryByteName: string = "0 MB"
    static hoverMemoryAbilityStruct: MemoryAbilityMonitorStruct | undefined;
    static selectMemoryAbilityStruct: MemoryAbilityMonitorStruct | undefined;
    cpu: number | undefined
    value: number | undefined
    startNS: number | undefined
    dur: number | undefined

    static draw(context2D: any, data: MemoryAbilityMonitorStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            let index = data.cpu || 0
            index += 2
            context2D.fillStyle = ColorUtils.colorForTid(index)
            context2D.strokeStyle = ColorUtils.colorForTid(index)
            if (data.startNS === MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct?.startNS) {
                context2D.lineWidth = 1;
                context2D.globalAlpha = 0.6;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / MemoryAbilityMonitorStruct.maxMemoryByte);
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
                context2D.beginPath()
                context2D.arc(data.frame.x, data.frame.y + data.frame.height - drawHeight, 3, 0, 2 * Math.PI, true)
                context2D.fill()
                context2D.globalAlpha = 1.0;
                context2D.stroke();
                context2D.beginPath()
                context2D.moveTo(data.frame.x + 3, data.frame.y + data.frame.height - drawHeight);
                context2D.lineWidth = 3;
                context2D.lineTo(data.frame.x + width, data.frame.y + data.frame.height - drawHeight)
                context2D.stroke();
            } else {
                context2D.globalAlpha = 0.6;
                context2D.lineWidth = 1;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0)) / MemoryAbilityMonitorStruct.maxMemoryByte);
                context2D.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
            }
        }
        context2D.globalAlpha = 1.0;
        context2D.lineWidth = 1;
    }
}
