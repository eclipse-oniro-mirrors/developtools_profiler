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
import {BaseStruct} from "./BaseStruct.js";
import {WakeupBean} from "./WakeupBean.js";

export class CpuStruct extends BaseStruct {
    static cpuCount: number //最大cpu数量
    static hoverCpuStruct: CpuStruct | undefined;
    static selectCpuStruct: CpuStruct | undefined;
    static wakeupBean: WakeupBean | null | undefined = null;
    cpu: number | undefined
    dur: number | undefined
    end_state: string | undefined
    id: number | undefined
    name: string | undefined
    priority: number | undefined
    processCmdLine: string | undefined
    processId: number | undefined
    processName: string | undefined
    schedId: number | undefined
    startTime: number | undefined
    tid: number | undefined
    type: string | undefined

    static draw(ctx: CanvasRenderingContext2D, data: CpuStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            if (data.processId === CpuStruct.hoverCpuStruct?.processId || !CpuStruct.hoverCpuStruct) {
                ctx.fillStyle = ColorUtils.colorForTid((data.processId || 0) > 0 ? (data.processId || 0) : (data.tid || 0))
            } else {
                ctx.fillStyle = "#e0e0e0"
            }
            ctx.fillRect(data.frame.x, data.frame.y, width, data.frame.height)
            if (width > textPadding * 2) {
                let process = `${(data.processName || "Process")} [${data.processId}]`
                let thread = `${data.name || "Thread"} [${data.tid}]`
                let processMeasure = ctx.measureText(process);
                let threadMeasure = ctx.measureText(thread);
                let processCharWidth = Math.round(processMeasure.width / process.length)
                let threadCharWidth = Math.round(threadMeasure.width / thread.length)
                ctx.fillStyle = "#ffffff"
                let y = data.frame.height / 2 + data.frame.y;
                if (processMeasure.width < width - textPadding * 2) {
                    let x1 = Math.floor(width / 2 - processMeasure.width / 2 + data.frame.x + textPadding)
                    ctx.textBaseline = "bottom";
                    ctx.fillText(process, x1, y, width - textPadding * 2)
                } else if (width - textPadding * 2 > processCharWidth * 4) {
                    let chatNum = (width - textPadding * 2) / processCharWidth;
                    let x1 = data.frame.x + textPadding
                    ctx.textBaseline = "bottom";
                    ctx.fillText(process.substring(0, chatNum - 4) + '...', x1, y, width - textPadding * 2)
                }
                if (threadMeasure.width < width - textPadding * 2) {
                    ctx.textBaseline = "top";
                    let x2 = Math.floor(width / 2 - threadMeasure.width / 2 + data.frame.x + textPadding)
                    ctx.fillText(thread, x2, y + 2, width - textPadding * 2)
                } else if (width - textPadding * 2 > threadCharWidth * 4) {
                    let chatNum = (width - textPadding * 2) / threadCharWidth;
                    let x1 = data.frame.x + textPadding
                    ctx.textBaseline = "top";
                    ctx.fillText(thread.substring(0, chatNum - 4) + '...', x1, y + 2, width - textPadding * 2)
                }
            }
            if (CpuStruct.selectCpuStruct && CpuStruct.equals(CpuStruct.selectCpuStruct, data)) {
                ctx.strokeStyle = '#232c5d'
                ctx.lineWidth = 2
                ctx.strokeRect(data.frame.x, data.frame.y, width - 2, data.frame.height)
            }
        }
    }

    static equals(d1: CpuStruct, d2: CpuStruct): boolean {
        if (d1 && d2 && d1.cpu == d2.cpu &&
            d1.tid == d2.tid &&
            d1.processId == d2.processId &&
            d1.startTime == d2.startTime &&
            d1.dur == d2.dur) {
            return true;
        } else {
            return false;
        }
    }
}

const textPadding = 2;

