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


export class HiperfEventRender  extends PerfRender{
    render(req: RequestMessage, list: Array<any>, filter: Array<any>, dataList2: Array<any>) {
        let groupBy10MS = req.scale > 100_000_000;
        if (req.lazyRefresh) {
            HiPerfEvent(list, dataList2, req.type!, filter, req.startNS, req.endNS, req.totalNS, req.frame, groupBy10MS, req.intervalPerf, req.useCache || !req.range.refresh);
        } else {
            if (!req.useCache) {
                HiPerfEvent(list, dataList2, req.type!, filter, req.startNS, req.endNS, req.totalNS, req.frame, groupBy10MS, req.intervalPerf, false);
            }
        }
        if (req.canvas) {
            req.context.clearRect(0, 0, req.frame.width, req.frame.height);
            let arr = filter;
            if (arr.length > 0 && !req.range.refresh && !req.useCache && req.lazyRefresh) {
                drawLoading(req.context, req.startNS, req.endNS, req.totalNS, req.frame, arr[0].startNS, arr[arr.length - 1].startNS + arr[arr.length - 1].dur)
            }
            drawLines(req.context, req.xs, req.frame.height, req.lineColor)
            req.context.stroke();
            req.context.beginPath();
            HiPerfEventStruct.hoverStruct = undefined;
            req.context.fillStyle = ColorUtils.FUNC_COLOR[0];
            req.context.strokeStyle = ColorUtils.FUNC_COLOR[0];
            if (req.isHover) {
                let offset = groupBy10MS ? 0 : 3;
                for (let re of filter) {
                    if (re.frame && req.hoverX >= re.frame.x - offset && req.hoverX <= re.frame.x + re.frame.width + offset) {//&& req.hoverY >= re.frame.y && req.hoverY <= re.frame.y + re.frame.height
                        HiPerfEventStruct.hoverStruct = re;
                        break;
                    }
                }
            } else {
                HiPerfEventStruct.hoverStruct = req.params.hoverStruct;
            }
            HiPerfEventStruct.selectStruct = req.params.selectStruct;
            let path = new Path2D();
            for (let re of filter) {
                HiPerfEventStruct.draw(req.context, path, re, groupBy10MS);
            }
            groupBy10MS ? req.context.fill(path) : req.context.stroke(path);
            drawSelection(req.context, req.params);
            let maxEvent = HiPerfEventStruct.maxEvent!.get(req.type!) || 0;
            let textMetrics = req.context.measureText(maxEvent);
            req.context.globalAlpha = 0.8
            req.context.fillStyle = "#f0f0f0"
            req.context.fillRect(0, 5, textMetrics.width + 8, 18)
            req.context.globalAlpha = 1
            req.context.fillStyle = "#333"
            req.context.textBaseline = "middle"
            req.context.fillText(maxEvent, 4, 5 + 9);
            req.context.stroke();
            req.context.closePath();
            drawFlagLine(req.context, req.flagMoveInfo, req.flagSelectedInfo, req.startNS, req.endNS, req.totalNS, req.frame, req.slicesTime);
        }
        // @ts-ignore
        self.postMessage({
            id: req.id,
            type: req.type,
            results: req.canvas ? undefined : filter,
            hover: HiPerfEventStruct.hoverStruct
        });
    }
}
export function HiPerfEvent(arr: Array<any>, arr2: any, type: string, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any, groupBy10MS: boolean, intervalPerf: number, use: boolean) {
    if (use && res.length > 0) {
        let pns = (endNS - startNS) / frame.width;
        let y = frame.y;
        for (let i = 0; i < res.length; i++) {
            let it = res[i];
            if ((it.startNS || 0) + (it.dur || 0) > startNS && (it.startNS || 0) < endNS) {
                if (!it.frame) {
                    it.frame = {};
                    it.frame.y = y;
                }
                it.frame.height = it.height;
                HiPerfEventStruct.setFrame(it, pns, startNS, endNS, frame);
            } else {
                it.frame = null;
            }
        }
        return;
    }
    res.length = 0;
    if (arr) {
        let list: Array<any>;
        if (groupBy10MS) {
            if (arr2[type] && arr2[type].length > 0) {
                list = arr2[type];
            } else {
                list = HiPerfEventStruct.groupBy10MS(arr, intervalPerf, type);
                arr2[type] = list;
            }
        } else {
            HiPerfEventStruct.groupBy10MS(arr, intervalPerf, type);
            list = arr;
        }
        let pns = (endNS - startNS) / frame.width;
        let y = frame.y;

        let groups = list.filter(it => (it.startNS || 0) + (it.dur || 0) > startNS && (it.startNS || 0) < endNS).map(it => {
            if (!it.frame) {
                it.frame = {};
                it.frame.y = y;
            }
            it.frame.height = it.height;
            HiPerfEventStruct.setFrame(it, pns, startNS, endNS, frame);
            return it;
        }).reduce((pre, current, index, arr) => {
            if (!pre[`${current.frame.x}`]) {
                pre[`${current.frame.x}`] = [];
                pre[`${current.frame.x}`].push(current);
                if (groupBy10MS) {
                    res.push(current);
                } else {
                    if (res.length == 0) {
                        res.push(current);
                    }
                    if (res[res.length - 1] && Math.abs(current.frame.x - res[res.length - 1].frame.x) > 4) {
                        res.push(current);
                    }
                }
            }
            return pre;
        }, {});
    }
}

export class HiPerfEventStruct extends BaseStruct {
    static hoverStruct: HiPerfEventStruct | undefined;
    static selectStruct: HiPerfEventStruct | undefined;
    static path = new Path2D('M 100,100 h 50 v 50 h 50');
    id: number | undefined;
    callchain_id: number | undefined;
    timestamp: number | undefined;
    thread_id: number | undefined;
    event_count: number | undefined;
    event_type_id: number | undefined;
    cpu_id: number | undefined;
    thread_state: string | undefined;
    startNS: number | undefined;
    endNS: number | undefined;
    dur: number | undefined;
    height: number | undefined;
    cpu: number | undefined;
    static maxEvent: Map<string, number> | undefined = new Map();
    sum: number | undefined;
    max: number | undefined;

    static draw(ctx: CanvasRenderingContext2D, path: Path2D, data: HiPerfEventStruct, groupBy10MS: boolean) {
        if (data.frame) {
            if (groupBy10MS) {
                let width = data.frame.width;
                path.rect(data.frame.x, 40 - (data.height || 0), width, data.height || 0)
            } else {
                path.moveTo(data.frame.x + 7, 20);
                HiPerfEventStruct.drawRoundRectPath(path, data.frame.x - 7, 20 - 7, 14, 14, 3)
                path.moveTo(data.frame.x, 27);
                path.lineTo(data.frame.x, 33);
            }
        }
    }

    static drawRoundRectPath(cxt: Path2D, x: number, y: number, width: number, height: number, radius: number) {
        cxt.arc(x + width - radius, y + height - radius, radius, 0, Math.PI / 2);
        cxt.lineTo(x + radius, y + height);
        cxt.arc(x + radius, y + height - radius, radius, Math.PI / 2, Math.PI);
        cxt.lineTo(x + 0, y + radius);
        cxt.arc(x + radius, y + radius, radius, Math.PI, Math.PI * 3 / 2);
        cxt.lineTo(x + width - radius, y + 0);
        cxt.arc(x + width - radius, y + radius, radius, Math.PI * 3 / 2, Math.PI * 2);
        cxt.lineTo(x + width, y + height - radius);
        cxt.moveTo(x + width / 3, y + height / 5);
        cxt.lineTo(x + width / 3, y + height / 5 * 4);
        cxt.moveTo(x + width / 3, y + height / 5);
        cxt.bezierCurveTo(x + width / 3 + 7, y + height / 5 - 2, x + width / 3 + 7, y + height / 5 + 6, x + width / 3, y + height / 5 + 4);
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

    static groupBy10MS(array: Array<any>, intervalPerf: number, type: string): Array<any> {
        let obj = array.map(it => {
            it.timestamp_group = Math.trunc(it.startNS / 1_000_000_0) * 1_000_000_0;
            return it;
        }).reduce((pre, current) => {
            (pre[current["timestamp_group"]] = pre[current["timestamp_group"]] || []).push(current);
            return pre;
        }, {});
        let arr: any[] = [];
        let max = 0;
        for (let aKey in obj) {
            let sum = obj[aKey].reduce((pre: any, cur: any) => {
                return pre + cur.event_count
            }, 0)
            if (sum > max) max = sum;
            let ns = parseInt(aKey);
            arr.push({
                startNS: ns,
                dur: 1_000_000_0,
                height: 0,
                sum: sum,
            })
        }
        if (typeof (HiPerfEventStruct.maxEvent!.get(type)) === "undefined") {
            HiPerfEventStruct.maxEvent!.set(type, max);
        }
        arr.map(it => {
            it.height = Math.floor(40 * it.sum / max);
            it.max = max;
            return it;
        })
        return arr;
    }
}
