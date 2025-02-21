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

import {ColorUtils} from "../component/trace/base/ColorUtils.js";
import {CpuStruct} from "./CpuStruct.js";
import {BaseStruct} from "./BaseStruct.js";

const padding = 1;

export class ProcessStruct extends BaseStruct {
    cpu: number | undefined
    dur: number | undefined
    id: number | undefined
    pid: number | undefined
    process: string | undefined
    startTime: number | undefined
    state: string | undefined
    thread: string | undefined
    tid: number | undefined
    ts: number | undefined
    type: string | undefined
    utid: number | undefined

    static draw(ctx: CanvasRenderingContext2D, data: ProcessStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            ctx.fillStyle = ColorUtils.colorForTid(data.pid || 0)
            let miniHeight = Math.round(data.frame.height / CpuStruct.cpuCount)
            ctx.fillRect(data.frame.x, data.frame.y + (data.cpu || 0) * miniHeight + padding, data.frame.width, miniHeight - padding * 2)
        }
    }
}