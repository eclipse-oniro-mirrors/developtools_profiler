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
import {Rect} from "../component/trace/timer-shaft/Rect.js";
import {ColorUtils} from "../component/trace/base/ColorUtils.js";

export class FuncStruct extends BaseStruct {
    static hoverFuncStruct: FuncStruct | undefined;
    static selectFuncStruct: FuncStruct | undefined;
    argsetid: number | undefined
    depth: number | undefined
    dur: number | undefined
    funName: string | undefined
    id: number | undefined
    is_main_thread: number | undefined
    parent_id: number | undefined
    startTs: number | undefined
    threadName: string | undefined
    tid: number | undefined
    identify:number |undefined
    track_id: number | undefined

    static draw(ctx: CanvasRenderingContext2D, data: FuncStruct) {
        if (data.frame) {
            if (data.dur == undefined || data.dur == null || data.dur == 0 || FuncStruct.isBinder(data)) {
            } else {
                let width = data.frame.width || 0;
                ctx.fillStyle = ColorUtils.FUNC_COLOR[data.depth || 0 % ColorUtils.FUNC_COLOR.length]
                let miniHeight = 20
                ctx.fillRect(data.frame.x, data.frame.y, data.frame.width, miniHeight - padding * 2)
                ctx.fillStyle = "#fff"
                FuncStruct.drawString(ctx, data.funName || '', 5, data.frame)
                if (FuncStruct.isSelected(data)) {
                    ctx.strokeStyle = "#000"
                    ctx.lineWidth = 1
                    ctx.strokeRect(data.frame.x, data.frame.y, data.frame.width, miniHeight - padding * 2)
                }
            }
        }
    }

    static drawString(ctx: CanvasRenderingContext2D, str: string, textPadding: number, frame: Rect) {
        let textMetrics = ctx.measureText(str);
        let charWidth = Math.round(textMetrics.width / str.length)
        if (textMetrics.width < frame.width - textPadding * 2) {
            let x2 = Math.floor(frame.width / 2 - textMetrics.width / 2 + frame.x + textPadding)
            ctx.fillText(str, x2, Math.floor(frame.y + frame.height / 2 + 2), frame.width - textPadding * 2)
            return;
        }
        if (frame.width - textPadding * 2 > charWidth * 4) {
            let chatNum = (frame.width - textPadding * 2) / charWidth;
            let x1 = frame.x + textPadding
            ctx.fillText(str.substring(0, chatNum - 4) + '...', x1, Math.floor(frame.y + frame.height / 2 + 2), frame.width - textPadding * 2)
            return;
        }
    }

    static isSelected(data: FuncStruct): boolean {
        return (FuncStruct.selectFuncStruct != undefined &&
            FuncStruct.selectFuncStruct.startTs == data.startTs &&
            FuncStruct.selectFuncStruct.dur == data.dur &&
            FuncStruct.selectFuncStruct.funName == data.funName)
    }

    static isBinder(data: FuncStruct): boolean {
        if (data.funName != null &&
            (
                data.funName.toLowerCase().startsWith("binder transaction")
                || data.funName.toLowerCase().startsWith("binder async")
                || data.funName.toLowerCase().startsWith("binder reply")
            )
        ) {
            return true;
        } else {
            return false;
        }
    }

    static isBinderAsync(data: FuncStruct): boolean {
        if (data.funName != null &&
            (
                data.funName.toLowerCase().includes("async")
            )
        ) {
            return true;
        } else {
            return false;
        }
    }
}

const padding = 1;
