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
import {ColorUtils} from "../component/trace/base/ColorUtils.js";

export class ProcessMemStruct extends BaseStruct {
    static hoverProcessMemStruct: ProcessMemStruct | undefined;
    trackId: number | undefined
    processName: string | undefined
    pid: number | undefined
    upid: number | undefined
    trackName: string | undefined
    type: string | undefined
    track_id: string | undefined
    value: number | undefined
    startTime: number | undefined
    duration: number | undefined
    maxValue: number | undefined
    delta: number | undefined;

    static draw(ctx: CanvasRenderingContext2D, data: ProcessMemStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            if (data.startTime === ProcessMemStruct.hoverProcessMemStruct?.startTime) {
                ctx.lineWidth = 1;
                ctx.globalAlpha = 0.6;
                let drawHeight: number = Math.floor(((data.value || 0) * (data.frame.height || 0) * 1.0) / (data.maxValue || 0));
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
                ctx.fillStyle = ColorUtils.colorForTid(data.maxValue || 0)
                ctx.strokeStyle = ColorUtils.colorForTid(data.maxValue || 0)
                ctx.globalAlpha = 0.6;
                ctx.lineWidth = 1;
                let drawHeight: number = ((data.value || 0) * (data.frame.height || 0) * 1.0) / (data.maxValue || 1);
                ctx.fillRect(data.frame.x, data.frame.y + data.frame.height - drawHeight, width, drawHeight)
            }
        }
        ctx.globalAlpha = 1.0;
        ctx.lineWidth = 1;
    }
}