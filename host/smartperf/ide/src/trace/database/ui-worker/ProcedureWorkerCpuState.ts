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
    drawLoading, drawSelection,
    drawWakeUp, ns2x, PerfRender, Render,
    RequestMessage
} from "./ProcedureWorkerCommon.js";
import {FileSysChartStruct} from "./ProcedureWorkerFileSystem.js";
import {FuncStruct} from "./ProcedureWorkerFunc.js";
import {SpFreqChart} from "../../component/chart/SpFreqChart.js";

export class CpuStateRender extends PerfRender{
    render(req:RequestMessage,list:Array<any>,filter:Array<any>,dataList2:Array<any>){
        if (req.lazyRefresh) {
            this.cpuState(list,dataList2,req.type!, filter,req.params.cpu,req.startNS, req.endNS, req.totalNS, req.frame, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                this.cpuState(list,dataList2,req.type!, filter,req.params.cpu,req.startNS, req.endNS, req.totalNS, req.frame, false);
            }
        }
        CpuStateStruct.hoverStateStruct = undefined;
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            if (filter.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, filter[0].startTs, filter[filter.length - 1].startTs + filter[filter.length - 1].dur)
            }
            req.context.beginPath();
            drawLines(req.context, req.xs, req.frame.height, req.lineColor);
            if (req.isHover) {
                let offset = 3;
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x - offset && req.hoverX <= re.frame.x + re.frame.width + offset) {
                        CpuStateStruct.hoverStateStruct = re;
                        break;
                    }
                }
            }
            CpuStateStruct.selectStateStruct = req.params.selectStateStruct;
            req.context.font = "11px sans-serif";
            req.context.fillStyle = req.chartColor;
            req.context.strokeStyle = req.chartColor;
            req.context.globalAlpha = 0.6;
            let path = new Path2D();
            for (let re of filter) {
                CpuStateStruct.draw(req.context, path,re);
            }
            req.context.fill(path);
            drawSelection(req.context, req.params);
            drawWakeUp(req.context, req.wakeupBean, req.startNS, req.endNS, req.totalNS, req.frame);
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        let msg = {
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: CpuStateStruct.hoverStateStruct
        }
        self.postMessage(msg);
    }

    cpuState(arr: Array<any>, arr2: any, type: string,res: Array<any>, cpu:number,startNS: number, endNS: number, totalNS: number, frame: any,use:boolean) {
        if (use && res.length > 0) {
            for (let i = 0, len = res.length; i < len; i++) {
                if ((res[i].startTs || 0) + (res[i].dur || 0) >= startNS && (res[i].startTs || 0) <= endNS) {
                    CpuStateStruct.setFrame(res[i], 5, startNS, endNS, totalNS, frame)
                } else {
                    res[i].frame = null;
                }
            }
            return;
        }
        res.length = 0;
        if (arr) {
            let list: Array<any> = [];
            if (arr2[type] && arr2[type].length > 0) {
                list = arr2[type];
            } else {
                list = this.getList(arr,endNS,cpu);
                arr2[type] = list;
            }
            let groups = list.filter(it => (it.startTs || 0) + (it.dur || 0) >= startNS && (it.startTs || 0) <= endNS).map(it => {
                CpuStateStruct.setFrame(it, 5, startNS, endNS, totalNS, frame)
                return it;
            }).reduce((pre, current, index, arr) => {
                (pre[`${current.frame.x}`] = pre[`${current.frame.x}`] || []).push(current);
                return pre;
            }, {});
            Reflect.ownKeys(groups).map((kv => {
                res.push(groups[kv].sort((a: any, b: any) => b.frame.width - a.frame.width)[0]);
                res.push(groups[kv].sort((a: any, b: any) => b.frame.height - a.frame.height)[0]);
            }));
        }
    }

    getList(arr:Array<any>,endNS:number,cpu:number):Array<any>{
        let heights = [4,12,21,30]
        for (let i = 0, len = arr.length; i < len; i++) {
            let it = arr[i];
            it.height = heights[it.value]
            it.cpu = cpu;
            if (i === arr.length - 1) {
                it.dur = (endNS || 0) - (it.startTs || 0)
            } else {
                it.dur = (arr[i + 1].startTs || 0) - (it.startTs || 0)
            }
        }
        return arr;
    }
}

export class CpuStateStruct extends BaseStruct {
    static hoverStateStruct:any;
    static selectStateStruct:any;
    dur: number | undefined
    value: string | undefined
    startTs: number | undefined
    height: number | undefined
    cpu:number | undefined

    static draw(ctx: CanvasRenderingContext2D,path:Path2D,data: CpuStateStruct) {
        if (data.frame) {
            if (data.startTs === CpuStateStruct.hoverStateStruct?.startTs || data.startTs === CpuStateStruct.selectStateStruct?.startTs) {
                path.rect(data.frame.x, 35 - (data.height || 0), data.frame.width, data.height || 0)
                ctx.lineWidth = 1;
                ctx.globalAlpha = 1.0;
                ctx.beginPath()
                ctx.arc(data.frame.x, 35 - (data.height || 0), 3, 0, 2 * Math.PI, true)
                ctx.stroke()
                ctx.beginPath()
                ctx.moveTo(data.frame.x + 3, 35 - (data.height || 0));
                ctx.lineWidth = 3;
                ctx.lineTo(data.frame.x + data.frame.width, 35 - (data.height || 0))
                ctx.stroke();
                ctx.lineWidth = 1;
                ctx.globalAlpha = 0.6;
                ctx.fillRect(data.frame.x, 35 - (data.height || 0), data.frame.width, data.height || 0)
            }else{
                ctx.globalAlpha = 0.6;
                path.rect(data.frame.x, 35 - (data.height || 0), data.frame.width, data.height || 0)
            }
        }
    }

    static setFrame(node: any, padding: number, startNS: number, endNS: number,totalNS:number, frame: any) {
        let x1: number, x2: number;
        if ((node.startTs || 0) < startNS) {
            x1 = 0;
        } else {
            x1 = ns2x((node.startTs || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startTs || 0) + (node.dur || 0) > endNS) {
            x2 = frame.width;
        } else {
            x2 = ns2x((node.startTs || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
        }
        let getV: number = x2 - x1 <= 1 ? 1 : x2 - x1;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.ceil(x1);
        node.frame.y = frame.y + padding;
        node.frame.width = Math.floor(getV);
        node.frame.height = node.height;
    }
}
