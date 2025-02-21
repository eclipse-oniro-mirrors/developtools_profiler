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

import {SpApplication} from "../SpApplication";

export function ns2s(ns: number): string {
    let second1 = 1_000_000_000; // 1 second
    let millisecond1 = 1_000_000; // 1 millisecond
    let microsecond1 = 1_000; // 1 microsecond
    let nanosecond1 = 1000.0;
    let res;
    if (ns >= second1) {
        res = (ns / 1000 / 1000 / 1000).toFixed(1) + " s";
    } else if (ns >= millisecond1) {
        res = (ns / 1000 / 1000).toFixed(1) + " ms";
    } else if (ns >= microsecond1) {
        res = (ns / 1000).toFixed(1) + " μs";
    } else if (ns > 0) {
        res = ns.toFixed(1) + " ns";
    } else {
        res = ns.toFixed(1) + " s";
    }
    return res;
}

export function ns2x(ns: number, startNS: number, endNS: number, duration: number, rect: any) {
    // @ts-ignore
    if (endNS == 0) {
        endNS = duration;
    }
    let xSize: number = (ns - startNS) * rect.width / (endNS - startNS);
    if (xSize < 0) {
        xSize = 0;
    } else if (xSize > rect.width) {
        xSize = rect.width;
    }
    return xSize;
}

export class Rect {
    x: number = 0
    y: number = 0
    width: number = 0
    height: number = 0

    constructor(x: number, y: number, width: number, height: number) {
        this.x = x;
        this.y = y;
        this.width = width;
        this.height = height;
    }

    static contains(rect: Rect, x: number, y: number): boolean {
        return rect.x <= x && x <= rect.x + rect.width && rect.y <= y && y <= rect.y + rect.height;
    }

    static containsWithPadding(rect: Rect, x: number, y: number, paddingLeftRight: number, paddingTopBottom: number): boolean {
        return rect.x + paddingLeftRight <= x
            && x <= rect.x + rect.width - paddingLeftRight
            && rect.y + paddingTopBottom <= y
            && y <= rect.y + rect.height - paddingTopBottom;
    }

    static containsWithMargin(rect: Rect, x: number, y: number, t: number, r: number, b: number, l: number): boolean {
        return rect.x - l <= x
            && x <= rect.x + rect.width + r
            && rect.y - t <= y
            && y <= rect.y + rect.height + b;
    }

    static intersect(r1: Rect, rect: Rect): boolean {
        let maxX = r1.x + r1.width >= rect.x + rect.width ? r1.x + r1.width : rect.x + rect.width;
        let maxY = r1.y + r1.height >= rect.y + rect.height ? r1.y + r1.height : rect.y + rect.height;
        let minX = r1.x <= rect.x ? r1.x : rect.x;
        let minY = r1.y <= rect.y ? r1.y : rect.y;
        if (maxX - minX <= rect.width + r1.width && maxY - minY <= r1.height + rect.height) {
            return true;
        } else {
            return false;
        }
    }

    contains(x: number, y: number): boolean {
        return this.x <= x && x <= this.x + this.width && this.y <= y && y <= this.y + this.height;
    }

    containsWithPadding(x: number, y: number, paddingLeftRight: number, paddingTopBottom: number): boolean {
        return this.x + paddingLeftRight <= x
            && x <= this.x + this.width - paddingLeftRight
            && this.y + paddingTopBottom <= y
            && y <= this.y + this.height - paddingTopBottom;
    }

    containsWithMargin(x: number, y: number, t: number, r: number, b: number, l: number): boolean {
        return this.x - l <= x
            && x <= this.x + this.width + r
            && this.y - t <= y
            && y <= this.y + this.height + b;
    }

    /**
     * 判断是否相交
     * @param rect
     */
    intersect(rect: Rect): boolean {
        let maxX = this.x + this.width >= rect.x + rect.width ? this.x + this.width : rect.x + rect.width;
        let maxY = this.y + this.height >= rect.y + rect.height ? this.y + this.height : rect.y + rect.height;
        let minX = this.x <= rect.x ? this.x : rect.x;
        let minY = this.y <= rect.y ? this.y : rect.y;
        if (maxX - minX <= rect.width + this.width && maxY - minY <= this.height + rect.height) {
            return true;
        } else {
            return false;
        }
    }
}

export class Point {
    x: number = 0
    y: number = 0

    constructor(x: number, y: number) {
        this.x = x;
        this.y = y;
    }
}

export class BaseStruct {
    frame: Rect | undefined
    isHover: boolean = false;
}


export class ColorUtils {
    public static GREY_COLOR: string = "#f0f0f0"
    /**
     * Color array of all current columns
     */
    public static MD_PALETTE: Array<string> = [
        "#3391ff",// red
        "#0076ff",// pink
        "#66adff",// purple
        "#2db3aa",// deep purple
        "#008078",// indigo
        "#73e6de",// blue
        "#535da6",// light blue
        "#38428c", // cyan
        "#7a84cc",// teal
        "#ff9201",// green
        "#ff7500",// light green
        "#ffab40",// lime
        "#2db4e2",// amber 0xffc105
        "#0094c6", // orange
        "#7cdeff",// deep orange
        "#ffd44a", // brown
        "#fbbf00",// blue gray
        "#ffe593",// yellow 0xffec3d
    ];
    public static FUNC_COLOR: Array<string> = [
        "#46B1E3",
        "#0094c6", // orange
        "#38428c",
        "#38778c",
        "#90708c",
        "#9c27b0",
        "#0076ff",// pink
        "#66adff",// purple
        "#2db4e2",
        "#7cdeff",// deep orange
        "#73e6de",// blue
        "#bcaaa4",
        "#2db3aa", // deep purple
        "#008078", // blue
        "#795548",
        // "#ffab40",// lime
        // "#c0ca33",
        "#ff7500",// light green
        "#ec407a",
    ];

    /**
     * Get the color value according to the length of the string
     *
     * @param str str
     * @param max max
     * @return int
     */
    public static hash(str: string, max: number): number {
        let colorA: number = 0x811c9dc5;
        let colorB: number = 0xfffffff;
        let colorC: number = 16777619;
        let colorD: number = 0xffffffff;
        let hash: number = colorA & colorB;

        for (let index: number = 0; index < str.length; index++) {
            hash ^= str.charCodeAt(index);
            hash = (hash * colorC) & colorD;
        }
        return Math.abs(hash) % max;
    }

    public static hashFunc(str: string, depth: number, max: number): number {
        let colorA: number = 0x811c9dc5;
        let colorB: number = 0xfffffff;
        let colorC: number = 16777619;
        let colorD: number = 0xffffffff;
        let hash: number = colorA & colorB;
        let st = str.replace(/[0-9]+/g, "");
        for (let index: number = 0; index < st.length; index++) {
            hash ^= st.charCodeAt(index);
            hash = (hash * colorC) & colorD;
        }
        return (Math.abs(hash) + depth) % max;
    }

    /**
     * Get color according to tid
     *
     * @param tid tid
     * @return Color
     */
    public static colorForTid(tid: number): string {
        let colorIdx: number = ColorUtils.hash(`${tid}`, ColorUtils.MD_PALETTE.length);
        return ColorUtils.MD_PALETTE[colorIdx];
    }

    public static formatNumberComma(str: number): string {
        let l = str.toString().split("").reverse();
        let t: string = "";
        for (let i = 0; i < l.length; i++) {
            t += l[i] + ((i + 1) % 3 == 0 && (i + 1) != l.length ? "," : "");
        }
        return t.split("").reverse().join("")
    }
}

export function drawLines(ctx: CanvasRenderingContext2D, xs: Array<any>, height: number, lineColor: string) {
    if (ctx) {
        ctx.lineWidth = 1;
        ctx.strokeStyle = lineColor || "#dadada";
        xs?.forEach(it => {
            ctx.moveTo(Math.floor(it), 0)
            ctx.lineTo(Math.floor(it), height)
        })
        ctx.stroke();
    }
}

export function drawFlagLine(ctx: any, hoverFlag: any, selectFlag: any, startNS: number, endNS: number, totalNS: number, frame: any, slicesTime: { startTime: number | null, endTime: number | null, color: string | null }) {
    if (ctx) {
        if (hoverFlag) {
            ctx.beginPath();
            ctx.lineWidth = 2;
            ctx.strokeStyle = hoverFlag?.color || "#dadada";
            ctx.moveTo(Math.floor(hoverFlag.x), 0)
            ctx.lineTo(Math.floor(hoverFlag.x), frame.height)
            ctx.stroke();
            ctx.closePath();
        }
        if (selectFlag) {
            ctx.beginPath();
            ctx.lineWidth = 2;
            ctx.strokeStyle = selectFlag?.color || "#dadada";
            selectFlag.x = ns2x(selectFlag.time, startNS, endNS, totalNS, frame);
            ctx.moveTo(Math.floor(selectFlag.x), 0)
            ctx.lineTo(Math.floor(selectFlag.x), frame.height)
            ctx.stroke();
            ctx.closePath();
        }
        if (slicesTime && slicesTime.startTime && slicesTime.endTime) {
            ctx.beginPath();
            ctx.lineWidth = 1;
            ctx.strokeStyle = slicesTime.color || "#dadada";
            let x1 = ns2x(slicesTime.startTime, startNS, endNS, totalNS, frame);
            let x2 = ns2x(slicesTime.endTime, startNS, endNS, totalNS, frame);
            ctx.moveTo(Math.floor(x1), 0)
            ctx.lineTo(Math.floor(x1), frame.height)
            ctx.moveTo(Math.floor(x2), 0)
            ctx.lineTo(Math.floor(x2), frame.height)
            ctx.stroke();
            ctx.closePath();
        }
    }
}

/**
 * get framechart color by percent
 * @param widthPercentage proportion of function
 * @returns rbg
 */
export function getHeatColor(widthPercentage: number) {
    return {
        r: Math.floor(245 + 10 * (1 - widthPercentage)),
        g: Math.floor(110 + 105 * (1 - widthPercentage)),
        b: 100,
    };
}

export enum ChartMode {
    Call,
    Byte,
    Count,
}

export class ChartStruct extends BaseStruct {
    static hoverFuncStruct: ChartStruct | undefined;
    static selectFuncStruct: ChartStruct | undefined;
    static lastSelectFuncStruct: ChartStruct | undefined;
    static padding: number = 1;
    needShow = false;
    depth: number = 0;
    symbol: string = '';
    size: number = 0;
    count: number = 0;
    type: ChartMode = ChartMode.Call;
    parent: ChartStruct | undefined;
    children: Array<ChartStruct> = [];

    /**
     * set function position
     * @param node current function struct
     * @param canvas_frame canvas
     * @param total all rect size
     */
    static setFuncFrame(node: ChartStruct, canvas_frame: Rect, total: number, mode: ChartMode) {
        if (!node.frame) {
            node.frame = new Rect(0, 0, 0, 0);
        }
        // filter depth is 0
        if (node.parent) {
            let idx = node.parent.children.indexOf(node);
            if (idx == 0) {
                node.frame!.x = node.parent.frame!.x;
            } else {
                // set x by left frame. left frame is parent.children[idx - 1]
                node.frame.x = node.parent.children[idx - 1].frame!.x + node.parent.children[idx - 1].frame!.width
            }
            if (mode == ChartMode.Byte) {
                node.frame!.width = Math.floor(node.size / total * canvas_frame.width);
            } else {
                node.frame!.width = Math.floor(node.count / total * canvas_frame.width);
            }
            node.frame!.y = node.parent.frame!.y + 20;
            node.frame!.height = 20;
        }
    }

    /**
     * draw rect
     * @param ctx CanvasRenderingContext2D
     * @param data rect which is need draw
     * @param percent function size or count / total size or count
     */
    static draw(ctx: CanvasRenderingContext2D, data: ChartStruct, percent: number) {
        let spApplication = <SpApplication>document.getElementsByTagName("sp-application")[0]
        if (data.frame) {
            // draw rect
            let miniHeight = 20;
            if (ChartStruct.isSelected(data)) {
                ctx.fillStyle = `rgba(${82}, ${145}, ${255}, 0.9)`;
            } else {
                let color = getHeatColor(percent);
                ctx.fillStyle = `rgba(${color.r}, ${color.g}, ${color.b}, 0.9)`;
            }
            ctx.fillRect(data.frame.x, data.frame.y, data.frame.width, miniHeight - ChartStruct.padding * 2);
            //draw border
            if (ChartStruct.isHover(data)) {
                if (spApplication.dark) {
                    ctx.strokeStyle = "#fff";
                } else {
                    ctx.strokeStyle = "#000";
                }
            } else {
                if (spApplication.dark) {
                    ctx.strokeStyle = "#000";
                } else {
                    ctx.strokeStyle = "#fff";
                }
            }
            ctx.lineWidth = 0.4;
            ctx.strokeRect(data.frame.x, data.frame.y, data.frame.width, miniHeight - ChartStruct.padding * 2);

            //draw symbol name
            if (data.frame.width > 10) {
                if (percent > 0.6 || ChartStruct.isSelected(data)) {
                    ctx.fillStyle = "#fff";
                } else {
                    ctx.fillStyle = "#000";
                }
                ChartStruct.drawString(ctx, data.symbol || '', 5, data.frame);
            }

        }
    }

    /**
     * draw function string in rect
     * @param ctx CanvasRenderingContext2D
     * @param str function Name
     * @param textPadding textPadding
     * @param frame canvas area
     * @returns is draw
     */
    static drawString(ctx: CanvasRenderingContext2D, str: string, textPadding: number, frame: Rect): boolean {
        let textMetrics = ctx.measureText(str);
        let charWidth = Math.round(textMetrics.width / str.length)
        if (textMetrics.width < frame.width - textPadding * 2) {
            let x2 = Math.floor(frame.width / 2 - textMetrics.width / 2 + frame.x + textPadding)
            ctx.fillText(str, x2, Math.floor(frame.y + frame.height / 2 + 2), frame.width - textPadding * 2)
            return true;
        }
        if (frame.width - textPadding * 2 > charWidth * 4) {
            let chatNum = (frame.width - textPadding * 2) / charWidth;
            let x1 = frame.x + textPadding
            ctx.fillText(str.substring(0, chatNum - 4) + '...', x1, Math.floor(frame.y + frame.height / 2 + 2), frame.width - textPadding * 2)
            return true;
        }
        return false;
    }

    static isHover(data: ChartStruct): boolean {
        return ChartStruct.hoverFuncStruct == data;
    }

    static isSelected(data: ChartStruct): boolean {
        return ChartStruct.lastSelectFuncStruct == data;
    }


}
