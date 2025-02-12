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

import {BaseStruct, ns2x, Rect} from "./ProcedureWorkerCommon.js";

export function thread(list: Array<any>, res: Array<any>, startNS: number, endNS: number, totalNS: number, frame: any,use:boolean) {
    if(use && res.length > 0){
        for (let i = 0; i < res.length; i++) {
            let it = res[i];
            if((it.startTime || 0) + (it.dur || 0) > startNS && (it.startTime || 0) < endNS){
                ThreadStruct.setThreadFrame(it, 5, startNS, endNS, totalNS, frame)
            }else{
                it.frame = null;
            }
        }
        return;
    }
    res.length = 0;
    if (list) {
        let groups = list.filter(it => (it.startTime || 0) + (it.dur || 0) > startNS && (it.startTime || 0) < endNS).map(it => {
            ThreadStruct.setThreadFrame(it, 5, startNS, endNS, totalNS, frame)
            return it;
        }).reduce((pre, current, index, arr) => {
            (pre[`${current.frame.x}`] = pre[`${current.frame.x}`] || []).push(current);
            return pre;
        }, {});
        Reflect.ownKeys(groups).map((kv => {
            let arr = (groups[kv].sort((a: any, b: any) => b.frame.width - a.frame.width));
            if (arr.length > 1) {
                let idx = arr.findIndex((it: any) => it.state != "S")
                if (idx != -1) {
                    res.push(arr[idx]);
                } else {
                    res.push(arr[0]);
                }
            } else {
                res.push(arr[0]);
            }
        }));
    }
}

const padding = 3;

export class ThreadStruct extends BaseStruct {
    static runningColor: string = "#467b3b";
    static rColor = "#a0b84d";
    static otherColor = "#673ab7";
    static uninterruptibleSleepColor = "#f19d38";
    static traceColor = "#0d47a1";
    static sColor = "#FBFBFB";
    static hoverThreadStruct: ThreadStruct | undefined;
    static selectThreadStruct: ThreadStruct | undefined;
    static statusMap: any = {
        "D": "Uninterruptible Sleep",
        "S": "Sleeping",
        "R": "Runnable",
        "Running": "Running",
        "R+": "Runnable (Preempted)",
        "DK": "Uninterruptible Sleep + Wake Kill",
        "I": "Task Dead",
        "T": "Traced",
        "t": "Traced",
        "X": "Exit (Dead)",
        "Z": "Exit (Zombie)",
        "K": "Wake Kill",
        "W": "Waking",
        "P": "Parked",
        "N": "No Load"
    }
    hasSched: number | undefined;// 14724852000
    pid: number | undefined// 2519
    processName: string | undefined //null
    threadName: string | undefined//"ACCS0"
    tid: number | undefined //2716
    upid: number | undefined // 1
    utid: number | undefined // 1
    cpu: number | undefined // null
    dur: number | undefined // 405000
    end_ts: number | undefined // null
    id: number | undefined // 1
    is_main_thread: number | undefined // 0
    name: string | undefined // "ACCS0"
    startTime: number | undefined // 58000
    start_ts: number | undefined // null
    state: string | undefined // "S"
    type: string | undefined // "thread"

    static setThreadFrame(node: any, padding: number, startNS: number, endNS: number, totalNS: number, frame: any) {
        let x1: number;
        let x2: number;
        if ((node.startTime || 0) < startNS) {
            x1 = 0;
        } else {
            x1 = ns2x((node.startTime || 0), startNS, endNS, totalNS, frame);
        }
        if ((node.startTime || 0) + (node.dur || 0) > endNS) {
            x2 = frame.width;
        } else {
            x2 = ns2x((node.startTime || 0) + (node.dur || 0), startNS, endNS, totalNS, frame);
        }
        let getV: number = x2 - x1 <= 1 ? 1 : x2 - x1;
        if (!node.frame) {
            node.frame = {};
        }
        node.frame.x = Math.floor(x1);
        node.frame.y = frame.y + padding;
        node.frame.width = Math.ceil(getV);
        node.frame.height = 30 - padding * 2;
    }

    static draw(ctx: CanvasRenderingContext2D, data: ThreadStruct) {
        if (data.frame) {
            ctx.globalAlpha = 1
            let stateText = data.state || '';
            if ("S" == data.state) {
                ctx.fillStyle = ThreadStruct.sColor;
                ctx.globalAlpha = 0.2; // transparency
                ctx.fillRect(data.frame.x, data.frame.y + padding, data.frame.width, data.frame.height - padding * 2)
                ctx.globalAlpha = 1; // transparency
            } else if ("R" == data.state || "R+" == data.state) {
                ctx.fillStyle = ThreadStruct.rColor;
                ctx.fillRect(data.frame.x, data.frame.y + padding, data.frame.width, data.frame.height - padding * 2)
                ctx.fillStyle = "#fff";
                data.frame.width > 4 && ThreadStruct.drawString(ctx, ThreadStruct.getEndState(data.state || ''), 2, data.frame);
            } else if ("D" == data.state) {
                ctx.fillStyle = ThreadStruct.uninterruptibleSleepColor;
                ctx.fillRect(data.frame.x, data.frame.y + padding, data.frame.width, data.frame.height - padding * 2)
                ctx.fillStyle = "#fff";
                data.frame.width > 4 && ThreadStruct.drawString(ctx, ThreadStruct.getEndState(data.state || ''), 2, data.frame);
            } else if ("Running" == data.state) {
                ctx.fillStyle = ThreadStruct.runningColor;
                ctx.fillRect(data.frame.x, data.frame.y + padding, data.frame.width, data.frame.height - padding * 2)
                ctx.fillStyle = "#fff";
                data.frame.width > 4 && ThreadStruct.drawString(ctx, ThreadStruct.getEndState(data.state || ''), 2, data.frame);
            } else if ("T" == data.state || "t" == data.state) {
                ctx.fillStyle = ThreadStruct.traceColor;
                ctx.fillRect(data.frame.x, data.frame.y + padding, data.frame.width, data.frame.height - padding * 2)
                ctx.fillStyle = "#fff";
                ThreadStruct.drawString(ctx, ThreadStruct.getEndState(data.state || ''), 2, data.frame);
            } else {
                ctx.fillStyle = ThreadStruct.otherColor;
                ctx.fillRect(data.frame.x, data.frame.y + padding, data.frame.width, data.frame.height - padding * 2)
                ctx.fillStyle = "#fff";
                data.frame.width > 4 && ThreadStruct.drawString(ctx, ThreadStruct.getEndState(data.state || ''), 2, data.frame);
            }
            if (ThreadStruct.selectThreadStruct && ThreadStruct.equals(ThreadStruct.selectThreadStruct, data) && ThreadStruct.selectThreadStruct.state != "S") {
                ctx.strokeStyle = '#232c5d'
                ctx.lineWidth = 2
                ctx.strokeRect(data.frame.x, data.frame.y + padding, data.frame.width - 2, data.frame.height - padding * 2)
            }
        }
    }

    static drawString(ctx: CanvasRenderingContext2D, str: string, textPadding: number, frame: Rect) {
        let textMetrics = ctx.measureText(str);
        let charWidth = Math.round(textMetrics.width / str.length)
        if (textMetrics.width < frame.width - textPadding * 2) {
            let x2 = Math.floor(frame.width / 2 - textMetrics.width / 2 + frame.x + textPadding)
            ctx.textBaseline = "middle"
            ctx.font = "8px sans-serif";
            ctx.fillText(str, x2, Math.floor(frame.y + frame.height / 2), frame.width - textPadding * 2)
            return;
        }
        if (frame.width - textPadding * 2 > charWidth * 4) {
            let chatNum = (frame.width - textPadding * 2) / charWidth;
            let x1 = frame.x + textPadding
            ctx.textBaseline = "middle"
            ctx.font = "8px sans-serif";
            ctx.fillText(str.substring(0, chatNum - 4) + '...', x1, Math.floor(frame.y + frame.height / 2), frame.width - textPadding * 2)
            return;
        }
    }

    static getEndState(state: string): string {
        let statusMapElement = ThreadStruct.statusMap[state];
        if (statusMapElement) {
            return statusMapElement
        } else {
            if ("" == statusMapElement || statusMapElement == null) {
                return "";
            }
            return "Unknown State";
        }
    }

    static equals(d1: ThreadStruct, d2: ThreadStruct): boolean {
        if (d1 && d2 && d1.cpu == d2.cpu &&
            d1.tid == d2.tid &&
            d1.state == d2.state &&
            d1.startTime == d2.startTime &&
            d1.dur == d2.dur) {
            return true;
        } else {
            return false;
        }
    }
}