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
    drawSelection, drawWakeUp, Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class EmptyRender extends Render{
    render(req: RequestMessage, list: Array<any>, filter: Array<any>){
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            req.context.beginPath();
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            drawSelection(req.context, req.params);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: null
        });
    }
}

export class CpuRender {
    render(req:RequestMessage,list:Array<any>,filter:Array<any>){
        if (req.lazyRefresh) {
            this.cpu(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                this.cpu(list, filter, req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startTime, arr[arr.length - 1].startTime + arr[arr.length - 1].dur)
            }
            req.context.beginPath();
            drawLines(req.context, req.xs, req.frame.height, req.lineColor);
            CpuStruct.hoverCpuStruct = undefined;
            if (req.isHover) {
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x && req.hoverX <= re.frame.x + re.frame.width && req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height) {
                        CpuStruct.hoverCpuStruct = re;
                        break;
                    }
                }
            } else {
                CpuStruct.hoverCpuStruct = req.params.hoverCpuStruct;
            }
            CpuStruct.selectCpuStruct = req.params.selectCpuStruct;
            req.context.font = "11px sans-serif";
            for (let re of filter) {
                CpuStruct.draw(req.context, re);
            }
            drawSelection(req.context, req.params);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
            let currentCpu = parseInt(req.type!.replace("cpu-data-", ""));
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame, req.type == `cpu-data-${CpuStruct.selectCpuStruct?.cpu || 0}` ? CpuStruct.selectCpuStruct : undefined, currentCpu);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: CpuStruct.hoverCpuStruct
        });
    }

    cpu(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any,use:boolean) {
        if(use && res.length > 0){
            let pns = (endNS - startNS) / frame.width;
            let y = frame.y + 5;
            let height = frame.height - 10;
            for (let i = 0, len = res.length; i < len; i++) {
                let it = res[i];
                if ((it.startTime || 0) + (it.dur || 0) > startNS && (it.startTime || 0) < endNS) {
                    if (!res[i].frame) {
                        res[i].frame = {};
                        res[i].frame.y = y;
                        res[i].frame.height = height;
                    }
                    CpuStruct.setCpuFrame(res[i], pns, startNS, endNS, frame)
                }else{
                    res[i].frame = null;
                }
            }
            return;
        }
        res.length = 0;
        if (list) {
            let pns = (endNS - startNS) / frame.width;
            let y = frame.y + 5;
            let height = frame.height - 10;
            for (let i = 0, len = list.length; i < len; i++) {
                let it = list[i];
                if ((it.startTime || 0) + (it.dur || 0) > startNS && (it.startTime || 0) < endNS) {
                    if (!it.frame) {
                        it.frame = {};
                        it.frame.y = y;
                        it.frame.height = height;
                    }
                    CpuStruct.setCpuFrame(it, pns, startNS, endNS, frame)
                    if (i > 0 && ((list[i - 1].frame?.x || 0) == (it.frame?.x || 0) && ((list[i - 1].frame?.width || 0) == (it.frame?.width || 0)))) {

                    } else {
                        res.push(it)
                    }
                }else{
                    it.frame = null;
                }
            }
        }
    }
}


let dec = new TextDecoder();
function rtCpu(buf: ArrayBuffer | null | undefined, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any) {
    if (buf) {
        res.length=0;
        let pns = (endNS - startNS) / frame.width;
        let y = frame.y + 5;
        let height = frame.height - 10;
        let str = dec.decode(buf);
        str = str.substring(str.indexOf("\n") + 1);
        let parse = JSON.parse(str);
        let columns = parse.columns;
        let values = parse.values;
        for (let i = 0; i < values.length; i++) {
            let obj: any = {}
            for (let j = 0; j < columns.length; j++) {
                obj[columns[j]] = values[i][j]
            }
            obj.frame = {
                // x: obj.x1,
                y: frame.y + 5,
                // width: obj.x2 - obj.x1 > 0 ? obj.x2 - obj.x1 : 1,
                height: frame.height - 10,
            }
            CpuStruct.setCpuFrame(obj, pns, startNS, endNS, frame)
            res.push(obj);
        }
    }else{
        let pns = (endNS - startNS) / frame.width;
        res.forEach(it=>{
            CpuStruct.setCpuFrame(it, pns, startNS, endNS, frame)
        })
    }
}

export class CpuStruct extends BaseStruct {
    static cpuCount: number = 1 //最大cpu数量
    static hoverCpuStruct: CpuStruct | undefined;
    static selectCpuStruct: CpuStruct | undefined;
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
            if (data.tid === CpuStruct.hoverCpuStruct?.tid || !CpuStruct.hoverCpuStruct) {
                ctx.globalAlpha = 1
                ctx.fillStyle = ColorUtils.colorForTid((data.processId || 0) > 0 ? (data.processId || 0) : (data.tid || 0))
            } else if(data.processId === CpuStruct.hoverCpuStruct?.processId ){
                ctx.globalAlpha = 0.6
                ctx.fillStyle = ColorUtils.colorForTid((data.processId || 0) > 0 ? (data.processId || 0) : (data.tid || 0))
            } else {
                ctx.globalAlpha = 1
                ctx.fillStyle = "#e0e0e0"
            }
            ctx.fillRect(data.frame.x, data.frame.y, width, data.frame.height)
            ctx.globalAlpha = 1
            if (width > textPadding * 2) {
                let process = `${(data.processName || "Process")} [${data.processId}]`
                let thread = `${data.name || "Thread"} [${data.tid}] [Prio:${data.priority||0}]`
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
                ctx.fillStyle = "#ffffff"
                ctx.font = "9px sans-serif";
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

    static setCpuFrame(node: any, pns: number, startNS: number, endNS: number, frame: any) {
        if ((node.startTime || 0) < startNS) {
            node.frame.x = 0;
        } else {
            node.frame.x = Math.floor(((node.startTime || 0) - startNS) / pns);
        }
        if ((node.startTime || 0) + (node.dur || 0) > endNS) {
            node.frame.width = frame.width - node.frame.x;
        } else {
            node.frame.width = Math.ceil(((node.startTime || 0) + (node.dur || 0) - startNS) / pns - node.frame.x);
        }
        if (node.frame.width < 1) {
            node.frame.width = 1;
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

export class WakeupBean {
    wakeupTime: number | undefined
    cpu: number | undefined
    process: string | undefined
    pid: number | undefined
    thread: string | undefined
    tid: number | undefined
    schedulingLatency: number | undefined
    schedulingDesc: string | undefined

}

const textPadding = 2;