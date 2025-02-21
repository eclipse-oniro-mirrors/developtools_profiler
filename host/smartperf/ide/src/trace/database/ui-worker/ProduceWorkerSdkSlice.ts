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
    drawWakeUp,
    ns2x,
    Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class SdkSliceRender extends Render {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>) {
        if (req.lazyRefresh) {
            this.sdkSlice(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                this.sdkSlice(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.canvas.width, req.canvas.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            req.context.beginPath();
            SdkSliceStruct.maxSdkSlice = req.params.maxSdkSlice;
            SdkSliceStruct.maxSdkSliceName = req.params.maxSdkSliceName;
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            SdkSliceStruct.hoverSdkSliceStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        SdkSliceStruct.hoverSdkSliceStruct = re;
                        break;
                    }
                }
            }
            SdkSliceStruct.selectSdkSliceStruct = req.params.selectSdkSliceStruct;
            for (let re of filter) {
                SdkSliceStruct.draw(req.context, re)
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            req.context.globalAlpha = 0.8
            req.context.fillStyle = "#f0f0f0"
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame);
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: SdkSliceStruct.hoverSdkSliceStruct
        });
    }

    sdkSlice(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, use: boolean) {
        if (use && res.length > 0) {
            for (let index = 0; index < res.length; index++) {
                let item = res[index];
                if ((item.end_ts || 0) > (startNS || 0) && (item.start_ts || 0) < (endNS || 0)) {
                    SdkSliceStruct.setSdkSliceFrame(res[index], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                } else {
                    res[index].frame = null;
                }
            }
            return;
        }
        res.length = 0;
        if (list) {
            for (let index = 0; index < list.length; index++) {
                let item = list[index];
                if ((item.end_ts || 0) > (startNS || 0) && (item.start_ts || 0) < (endNS || 0)) {
                    SdkSliceStruct.setSdkSliceFrame(list[index], 5, startNS || 0, endNS || 0, totalNS || 0, frame)
                    if (index > 0 && ((list[index - 1].frame?.x || 0) == (list[index].frame?.x || 0) && (list[index - 1].frame?.width || 0) == (list[index].frame?.width || 0))) {

                    } else {
                        res.push(item)
                    }
                }
            }
        }
    }
}

export class SdkSliceStruct extends BaseStruct {
    static maxSdkSlice: number = 0
    static maxSdkSliceName: string = ""
    static hoverSdkSliceStruct: SdkSliceStruct | undefined;
    static selectSdkSliceStruct: SdkSliceStruct | undefined;

    start_ts: number | undefined
    end_ts: number | undefined

    value: number | undefined
    slice_message: string | undefined

    static draw(ctx: CanvasRenderingContext2D, data: SdkSliceStruct) {
        if (data.frame) {
            let width = data.frame.width || 0;
            let index = 4;
            ctx.fillStyle = "#6DC0DC"
            ctx.strokeStyle = "#6DC0DC"
            if (data.start_ts === SdkSliceStruct.hoverSdkSliceStruct?.start_ts) {
                ctx.lineWidth = 1;
                ctx.fillRect(data.frame.x, data.frame.y + 4, width, data.frame.height)
                ctx.beginPath()
                ctx.arc(data.frame.x, data.frame.y + 4, 3, 0, 2 * Math.PI, true)
                ctx.fill()
                ctx.globalAlpha = 1.0;
                ctx.stroke();
                ctx.beginPath()
                ctx.moveTo(data.frame.x + 3, data.frame.y + 4);
                ctx.lineWidth = 3;
                ctx.lineTo(data.frame.x + width, data.frame.y + 4)
                ctx.stroke();
            } else {
                ctx.lineWidth = 1;
                ctx.fillRect(data.frame.x, data.frame.y + 4, width, data.frame.height)
            }
        }
    }

    static setSdkSliceFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let startPointX: number, endPointX: number

        if ((node.start_ts || 0) < startNS) {
            startPointX = 0
        } else {
            startPointX = ns2x((node.start_ts || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.end_ts || 0) > endNS) {
            endPointX = frame.width;
        } else {
            endPointX = ns2x((node.end_ts || 0), startNS, endNS, totalNS, frame);
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
