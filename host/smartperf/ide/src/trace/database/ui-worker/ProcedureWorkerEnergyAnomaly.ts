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

import { ColorUtils } from "../../component/trace/base/ColorUtils.js";
import {
    BaseStruct,
    drawFlagLine,
    drawLines,
    drawLoading,
    drawSelection,
    PerfRender,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class EnergyAnomalyRender extends PerfRender {
    render(req: RequestMessage, list: Array<any>, filter: Array<any>,dataList2:Array<any>){
        if (req.lazyRefresh) {
            anomaly(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.params.appName, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                anomaly(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.params.appName, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.canvas.width, req.canvas.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS)
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            req.context.stroke();
            req.context.beginPath();
            EnergyAnomalyStruct.hoverEnergyAnomalyStruct = undefined;
            if (req.isHover) {
                let offset = 3;
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x - offset && req.hoverX <= re.frame.x + re.frame.width + offset) {
                        EnergyAnomalyStruct.hoverEnergyAnomalyStruct = re;
                        break;
                    }
                }
            } else {
                EnergyAnomalyStruct.hoverEnergyAnomalyStruct = req.params.hoverStruct;
            }
            EnergyAnomalyStruct.selectEnergyAnomalyStruct = req.params.selectEnergyAnomalyStruct;
            req.context.fillStyle = ColorUtils.FUNC_COLOR[0]
            req.context.strokeStyle = ColorUtils.FUNC_COLOR[0];
            let path = new Path2D();
            for (let re of filter) {
                EnergyAnomalyStruct.draw(req.context, path, re);
            }
            req.context.fillStyle = "#E64566";
            req.context.strokeStyle = "#E64566";
            req.context.fillRect(req.canvas.width - 290, 12, 8, 8);
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText("System Abnormality", req.canvas.width - 225, 18)
            req.context.stroke(path);
            req.context.fillStyle = "#FFC880";
            req.context.strokeStyle = "#FFC880";
            req.context.fillRect(req.canvas.width - 145, 12, 8, 8);
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText("Application Abnormality", req.canvas.width - 70, 18)
            req.context.stroke(path);
            drawSelection(req.context, req.params);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: EnergyAnomalyStruct.hoverEnergyAnomalyStruct
        });
    }
}

export function anomaly(arr: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, appName: string | undefined, use: boolean) {
    if (use && res.length > 0 ) {
        let pns = (endNS - startNS) / frame.width;
        let y = frame.y;
        for (let i = 0; i < res.length; i++) {
            let it = res[i];
            if((it.startNS || 0) > startNS && (it.startNS || 0) < endNS){
                if (!it.frame) {
                    it.frame = {};
                    it.frame.y = y;
                }
                it.frame.height = it.height;
                EnergyAnomalyStruct.setAnomalyFrame(it, pns, startNS, endNS, frame);
            }else{
                it.frame = null;
            }
        }
        return;
    }

    res.length = 0;
    if (arr) {
        let y = frame.y;
        let pns = (endNS - startNS) / frame.width;
        for (let index = 0; index < arr.length; index++) {
            let item = arr[index];
            if (!item.frame) {
                item.frame = {};
                item.frame.y = y;
            }
            item.frame.height = item.height;
            if ((item.startNS + 50000) > (startNS || 0) && (item.startNS || 0) < (endNS || 0)) {
                EnergyAnomalyStruct.setAnomalyFrame(item, pns, startNS || 0, endNS || 0, frame)
                if ((item.appKey === "APPNAME" && item.Value.indexOf(appName) >= 0)) {
                    res.push(item)
                }
                if (item.appKey != "APPNAME") {
                    res.push(item)
                }
            }
        }
    }
}

export class EnergyAnomalyStruct extends BaseStruct {
    static hoverEnergyAnomalyStruct: EnergyAnomalyStruct | undefined;
    static selectEnergyAnomalyStruct: EnergyAnomalyStruct | undefined;
    static SYSTEM_EXCEPTION = new Set(["ANOMALY_SCREEN_OFF_ENERGY", "ANOMALY_ALARM_WAKEUP",
        "ANOMALY_KERNEL_WAKELOCK", "ANOMALY_CPU_HIGH_FREQUENCY", "ANOMALY_WAKEUP"]);
    type: number | undefined
    startNS: number | undefined
    height: number | undefined
    eventName: string | undefined

    static draw(ctx: CanvasRenderingContext2D, path: Path2D, data: EnergyAnomalyStruct) {
        if (data.frame) {
            EnergyAnomalyStruct.drawRoundRectPath(ctx, data.frame.x - 7, 20 - 7, 14, data)
        }

    }

    static drawRoundRectPath(ctx: CanvasRenderingContext2D, x: number, y: number, width: number, data: EnergyAnomalyStruct) {
        ctx.beginPath();
        ctx.arc(x + 7, y + 22, 3, 0, Math.PI * 2);
        ctx.closePath();
        let color = "";
        if(EnergyAnomalyStruct.SYSTEM_EXCEPTION.has(<string>data.eventName)){
            color = '#E64566';
        }else {
            color = "#FFC880";
        }
        // 填充背景颜色
        ctx.fillStyle = color;
        ctx.fill();
        // 填充边框颜色
        ctx.lineWidth = width;
        ctx.lineCap = 'round'
        ctx.strokeStyle = color
        ctx.stroke();
        // 填充文字颜色
        ctx.font = "12px Arial";
        ctx.fillStyle = ColorUtils.GREY_COLOR;
        ctx.textAlign = "center";
        ctx.fillText("E", x + 7, y + 23);
    }

    static setAnomalyFrame(node: any, pns: number, startNS: number, endNS: number, frame: any) {
        if ((node.startNS || 0) < startNS) {
            node.frame.x = 0;
        } else {
            node.frame.x = Math.floor(((node.startNS || 0) - startNS) / pns);
        }
        if ((node.startNS || 0) > endNS) {
            node.frame.width = frame.width - node.frame.x;
        } else {
            node.frame.width = Math.ceil(((node.startNS || 0) - startNS) / pns - node.frame.x);
        }
        if (node.frame.width < 1) {
            node.frame.width = 1;
        }
    }
}





