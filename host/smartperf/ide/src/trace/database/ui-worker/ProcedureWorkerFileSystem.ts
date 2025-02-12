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
    drawSelection, PerfRender,
    RequestMessage
} from "./ProcedureWorkerCommon.js";

export class FileSystemRender extends PerfRender{
    render(req: RequestMessage, list: Array<any>, filter: Array<any>,dataList2:Array<any>){
        let groupBy10MS = req.scale > 20_000_000;
        let isDiskIO :boolean = req.type!.includes("disk-io");
        if(isDiskIO){
            groupBy10MS = true;
        }
        if (req.lazyRefresh) {
            fileSysChart(list, dataList2, req.type!, filter, req.startNS, req.endNS, req.totalNS, req.frame, groupBy10MS, isDiskIO,req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                fileSysChart(list, dataList2, req.type!, filter, req.startNS, req.endNS, req.totalNS, req.frame, groupBy10MS, isDiskIO,false);
            }
        }
        let hoverStruct : FileSysChartStruct | undefined;
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            req.context.stroke();
            req.context.beginPath();
            if (req.isHover) {
                let offset = groupBy10MS ? 0 : 3;
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x - offset && req.hoverX <= re.frame.x + re.frame.width + offset) {//&& req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height
                        hoverStruct = re;
                        break;
                    }
                }
            }
            req.context.fillStyle = req.chartColor ?? ColorUtils.MD_PALETTE[0];
            req.context.strokeStyle = req.chartColor ?? ColorUtils.MD_PALETTE[0];
            let path = new Path2D();
            for (let re of filter) {
                FileSysChartStruct.draw(req.context, path, re, groupBy10MS);
            }
            req.context.fill(path);
            drawSelection(req.context, req.params);
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        let msg = {
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: hoverStruct
        }
        self.postMessage(msg);
    }
}

export function fileSysChart(arr: Array<any>, arr2: any, type: string, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, groupBy10MS: boolean, isDiskIO:boolean,use: boolean) {
    if (use && res.length > 0 ) {//&& !groupBy10MS
        let pns = (endNS - startNS) / frame.width;
        let y = frame.y;
        for (let i = 0; i < res.length; i++) {
            let it = res[i];
            if((it.startNS || 0) + (it.dur || 0) > startNS && (it.startNS || 0) < endNS){
                if (!it.frame) {
                    it.frame = {};
                    it.frame.y = y;
                }
                it.frame.height = it.height;
                FileSysChartStruct.setFrame(it, pns, startNS, endNS, frame);
            }else{
                it.frame = null;
            }
        }
        return;
    }
    res.length = 0;
    if(arr){
        let list: Array<any> = [];
        let pns = (endNS - startNS) / frame.width;
        let y = frame.y;
        if(groupBy10MS){
            if (arr2[type] && arr2[type].length > 0) {
                list = arr2[type];
            } else {
                list = isDiskIO ? FileSysChartStruct.groupBy10MSWithMaxLatency(arr) : FileSysChartStruct.groupBy10MSWithCount(arr);
                arr2[type] = list;
            }
            list = list.filter(it => (it.startNS || 0) + (it.dur || 0) > startNS && (it.startNS || 0) < endNS);
            let groups = list.map(it => {
                if (!it.frame) {
                    it.frame = {};
                    it.frame.y = y;
                }
                it.frame.height = it.height;
                FileSysChartStruct.setFrame(it, pns, startNS, endNS, frame);
                return it;
            }).reduce((pre, current, index, arr) => {
                (pre[`${current.frame.x}`] = pre[`${current.frame.x}`] || []).push(current);
                return pre;
            }, {});
            Reflect.ownKeys(groups).map((kv => {
                // let arr = (groups[kv].sort((a: any, b: any) => b.frame.width - a.frame.width));
                res.push(groups[kv][0]);
            }));
        }else{
            let filter = arr.filter(it => (it.startNS || 0) + (it.dur || 0) > startNS && (it.startNS || 0) < endNS);
            list = FileSysChartStruct.computeHeightNoGroup(filter,totalNS);
            list.map(it => {
                if (!it.frame) {
                    it.frame = {};
                    it.frame.y = y;
                }
                it.frame.height = it.height;
                FileSysChartStruct.setFrame(it, pns, startNS, endNS, frame);
                res.push(it);
            })
        }
    }
}

export class FileSysChartStruct extends BaseStruct {
    startNS: number | undefined;
    endNS: number | undefined;
    dur: number | undefined;
    size: number | undefined;
    height: number | undefined;
    group10Ms: boolean | undefined;

    static draw(ctx: CanvasRenderingContext2D, path: Path2D, data: FileSysChartStruct, groupBy10MS: boolean) {
        if (data.frame) {
            let width = data.frame.width;
            path.rect(data.frame.x, 40 - (data.height || 0), width, data.height || 0)
        }
    }

    static setFrame(node: any, pns: number, startNS: number, endNS: number, frame: any) {
        if ((node.startNS || 0) < startNS) {
            node.frame.x = 0;
        } else {
            node.frame.x = Math.floor(((node.startNS || 0) - startNS) / pns);
        }
        if ((node.startNS || 0) + (node.dur || 0) > endNS) {
            node.frame.width = frame.width - node.frame.x;
        } else {
            node.frame.width = Math.ceil(((node.startNS || 0) + (node.dur || 0) - startNS) / pns - node.frame.x);
        }
        if (node.frame.width < 1) {
            node.frame.width = 1;
        }
    }

    static computeHeightNoGroup(array:Array<any>,totalNS:number):Array<any>{
        if(array.length > 0){
            let time :Array<{time:number,type:number}> = [];
            array.map((item) => {
                time.push({time:item.startNS,type:1});
                time.push({time:item.endNS || totalNS,type:-1});
            })
            time = time.sort((a,b) => a.time - b.time);
            let arr:Array<any> = [];
            let first = {
                startNS: time[0].time ?? 0,
                dur: 0,
                size:1,
                group10Ms:false,
                height:1,
            };
            arr.push(first);
            let max = 2
            for (let i = 1,len = time.length; i < len; i++) {
                let heap = {
                    startNS: time[i].time,
                    dur: 0,
                    size:0,
                    group10Ms:false,
                    height: 0
                };
                arr[i - 1].dur = heap.startNS - arr[i - 1].startNS;
                if (i == len - 1) {
                    heap.dur = totalNS - heap.startNS;
                }
                heap.size = arr[i - 1].size + time[i].type;
                heap.height = Math.floor(heap.size / 6 * 36);
                max = max > heap.size ? max : heap.size;
                arr.push(heap)
            }
            arr.map(it => it.height = Math.floor(it.size / max * 36))
            return arr;
        }else{
            return [];
        }
    }

    static groupBy10MSWithCount(array: Array<any>): Array<any> {
        let obj = array.map(it => {
            it.timestamp_group = Math.trunc(it.startNS / 1_000_000_0) * 1_000_000_0;
            return it;
        }).reduce((pre, current) => {
            (pre[current["timestamp_group"]] = pre[current["timestamp_group"]] || []).push(current);
            return pre;
        }, {});
        let arr: any[] = [];
        let max = 1;
        for (let aKey in obj) {
            max = obj[aKey].length > max ? obj[aKey].length : max
        }
        for (let aKey in obj) {
            let ns = parseInt(aKey);
            let height: number = Math.floor(obj[aKey].length / max * 36);
            arr.push({
                startNS: ns,
                dur: 1_000_000_0,
                group10Ms:true,
                size:obj[aKey].length,
                height: height,
            })
        }
        return arr;
    }

    static groupBy10MSWithMaxLatency(array: Array<any>): Array<any> {
        let obj = array.map(it => {
            it.timestamp_group = Math.trunc(it.startNS / 1_000_000_0) * 1_000_000_0;
            return it;
        }).reduce((pre, current) => {
            if(pre[current["timestamp_group"]] == undefined || pre[current["timestamp_group"]] == null){
                pre[current["timestamp_group"]] = [];
            }
            if(pre[current["timestamp_group"]].length > 0){
                let p = pre[current["timestamp_group"]][0];
                if(p.dur < current.dur){
                    pre[current["timestamp_group"]][0] = current;
                }
            }else{
                pre[current["timestamp_group"]][0] = current;
            }
            return pre;
        }, {});
        let arr: any[] = [];
        let max = 1;
        for (let aKey in obj) {
            max = obj[aKey][0].dur > max ? obj[aKey][0].dur : max
        }
        for (let aKey in obj) {
            let ns = parseInt(aKey);
            let height: number = Math.floor(obj[aKey][0].dur / max * 36);
            arr.push({
                startNS: ns,
                dur: 1_000_000_0,
                group10Ms:true,
                size:obj[aKey][0].dur,
                height: height,
            })
        }
        return arr;
    }
}