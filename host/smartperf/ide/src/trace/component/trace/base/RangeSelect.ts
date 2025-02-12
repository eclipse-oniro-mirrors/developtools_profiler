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

import {RangeSelectStruct, TraceRow} from "./TraceRow.js";
import {Rect} from "../timer-shaft/Rect.js";
import {ns2x, TimerShaftElement} from "../TimerShaftElement.js";
import {info} from "../../../../log/Log.js";

export class RangeSelect {
    rowsEL: HTMLDivElement | undefined | null;
    isMouseDown: boolean = false;
    public rangeTraceRow: Array<TraceRow<any>> | undefined
    public selectHandler: ((ds: Array<TraceRow<any>>, refreshCheckBox: boolean) => void) | undefined;
    private startX: number = 0
    private endX: number = 0;
    private startY: number = 0
    private endY: number = 0;
    private startY2: number = 0
    private endY2: number = 0;
    private timerShaftEL: TimerShaftElement | null | undefined;
    private timerShaftDragEL: HTMLDivElement | null | undefined;
    private isHover: boolean = false;
    private movingMark: string = "";
    private mark: { startMark: number, endMark: number } = {startMark: 0, endMark: 0}
    private spacerEL: HTMLDivElement;

    constructor(timerShaftEL: TimerShaftElement | null | undefined) {
        this.timerShaftEL = timerShaftEL;
        this.timerShaftDragEL = this.timerShaftEL?.shadowRoot?.querySelector(".total > div:nth-child(1)");
        this.spacerEL = this.timerShaftEL?.nextElementSibling! as HTMLDivElement;
    }

    isInRowsEl(ev: MouseEvent): boolean {
        return (ev.offsetY > this.timerShaftDragEL!.clientHeight! &&
            ev.offsetY < this.rowsEL!.offsetTop + this.rowsEL!.offsetHeight &&
            ev.offsetX > this.rowsEL!.offsetLeft! &&
            ev.offsetX < this.rowsEL!.offsetLeft + this.rowsEL!.offsetWidth
        )
    }

    isInSpacerEL(ev: MouseEvent): boolean {
        return (ev.offsetY > this.spacerEL.offsetTop &&
            ev.offsetY < this.spacerEL.offsetTop + this.spacerEL.offsetHeight &&
            ev.offsetX > this.spacerEL.offsetLeft! &&
            ev.offsetX < this.spacerEL.offsetLeft + this.spacerEL.offsetWidth
        )
    }

    mouseDown(ev: MouseEvent) {
        if (this.isHover) {
            this.isMouseDown = true;
            return;
        }
        if (this.isInRowsEl(ev)) {
            this.rangeTraceRow = [];
            this.isMouseDown = true;
            TraceRow.rangeSelectObject = undefined;
            this.startX = ev.offsetX - this.rowsEL!.offsetLeft!;
            if (this.isInSpacerEL(ev)) {
                this.startY = 0;
                this.startY2 = ev.offsetY + 48;
            } else {
                this.startY = ev.offsetY - this.rowsEL!.offsetTop!;
                this.startY2 = this.spacerEL.offsetTop + this.spacerEL.offsetHeight! + 48;
            }
        }
    }

    mouseUp(ev: MouseEvent) {
        if (this.isInRowsEl(ev) && this.isDrag()) {
            this.endX = ev.offsetX - this.rowsEL!.offsetLeft!;
            if (this.isInSpacerEL(ev)) {
                this.endY = ev.offsetY - this.rowsEL!.clientTop! + this.rowsEL!.offsetTop!;
                this.endY2 = ev.offsetY + 48;
            } else {
                this.endY = ev.offsetY - this.rowsEL!.clientTop! + this.rowsEL!.offsetTop!;
                this.endY2 = this.spacerEL.offsetTop + this.spacerEL.offsetHeight! + 48;
            }
            if (this.selectHandler) {
                this.selectHandler(this.rangeTraceRow || [], !this.isHover);
            }
        }
        this.isMouseDown = false;
    }

    isDrag(): boolean {
        return this.startX != this.endX && (this.startY != this.endY || this.startY2 != this.endY2)
    }

    isTouchMark(ev: MouseEvent): boolean {
        let notTimeHeight: boolean = ev.offsetY > (this.timerShaftDragEL!.clientHeight || 0)
        if (!notTimeHeight) {
            this.isHover = false;
            return false
        }
        if ((this.rangeTraceRow ? this.rangeTraceRow.length == 0 : false) && !this.isMouseDown) {
            this.isHover = false;
        }
        return notTimeHeight && (this.rangeTraceRow ? this.rangeTraceRow.length > 0 : false) && !this.isMouseDown
    }

    mouseMove(rows: Array<TraceRow<any>>, ev: MouseEvent) {
        if (this.isTouchMark(ev) && TraceRow.rangeSelectObject) {
            info( "isTouchMark");
            let markA = ns2x(TraceRow.rangeSelectObject!.startNS!, TraceRow.range!.startNS, TraceRow.range!.endNS, TraceRow.range!.totalNS!, {width: this.timerShaftEL?.canvas?.clientWidth || 0} as Rect);
            let markB = ns2x(TraceRow.rangeSelectObject!.endNS!, TraceRow.range!.startNS, TraceRow.range!.endNS, TraceRow.range!.totalNS!, {width: this.timerShaftEL?.canvas?.clientWidth || 0} as Rect);
            this.mark = {startMark: markA, endMark: markB};
            let mouseX = ev.offsetX - (this.timerShaftEL?.totalEL?.clientWidth || 0)
            if ((mouseX > markA - 5 && mouseX < markA + 5)) {
                this.isHover = true;
                document.body.style.cursor = "ew-resize"
                this.movingMark = markA < markB ? "markA" : "markB"
            } else if (mouseX > markB - 5 && mouseX < markB + 5) {
                this.isHover = true;
                document.body.style.cursor = "ew-resize"
                this.movingMark = markB < markA ? "markA" : "markB"
            } else {
                this.isHover = false;
            }
        }
        if (this.isHover && this.isMouseDown) {
            let rangeSelect: RangeSelectStruct | undefined;
            this.rangeTraceRow = rows.filter(it => {
                if (it.rangeSelect) {
                    if (!rangeSelect) {
                        rangeSelect = new RangeSelectStruct();
                        let mouseX = ev.offsetX - this.rowsEL!.offsetLeft! - (it.canvasContainer?.offsetLeft || 248)
                        let markA = this.movingMark == "markA" ? mouseX : this.mark.startMark;
                        let markB = this.movingMark == "markB" ? mouseX : this.mark.endMark;
                        let startX = markA < markB ? markA : markB
                        let endX = markB < markA ? markA : markB
                        rangeSelect.startX = startX;
                        rangeSelect.endX = endX;
                        rangeSelect.startNS = Math.floor((TraceRow.range!.endNS - TraceRow.range!.startNS) * startX / it.frame.width + TraceRow.range!.startNS!);
                        rangeSelect.endNS = Math.floor((TraceRow.range!.endNS - TraceRow.range!.startNS) * endX / it.frame.width + TraceRow.range!.startNS!);
                        if (rangeSelect.startNS <= TraceRow.range!.startNS) {
                            rangeSelect.startNS = TraceRow.range!.startNS
                        }
                        if (rangeSelect.endNS >= TraceRow.range!.endNS) {
                            rangeSelect.endNS = TraceRow.range!.endNS
                        }
                    }
                    TraceRow.rangeSelectObject = rangeSelect;
                    return true
                }
            })
            this.timerShaftEL!.sportRuler!.isRangeSelect = (this.rangeTraceRow?.length || 0) > 0;
            this.timerShaftEL!.sportRuler!.draw();
            return;
        }
        if (!this.isMouseDown) {
            this.timerShaftEL!.sportRuler!.isRangeSelect = (this.rangeTraceRow?.length || 0) > 0;
            this.timerShaftEL!.sportRuler!.draw();
            return;
        }
        this.endX = ev.offsetX - this.rowsEL!.offsetLeft!;
        if (this.isInSpacerEL(ev)) {
            this.endY = 0;
            this.endY2 = ev.offsetY + 48;
        } else {
            this.endY = ev.offsetY - this.rowsEL!.offsetTop!;
            this.endY2 = this.spacerEL.offsetTop + this.spacerEL.offsetHeight! + 48;
        }
        let scrollTop = this.rowsEL?.scrollTop || 0
        let xMin = this.startX < this.endX ? this.startX : this.endX;
        let xMax = this.startX > this.endX ? this.startX : this.endX;
        let yMin = this.startY < this.endY ? this.startY : this.endY;
        let yMax = this.startY > this.endY ? this.startY : this.endY;
        let rangeSelect: RangeSelectStruct | undefined;
        this.rangeTraceRow = rows.filter(it => {
            let rt: Rect;
            let canvasOffsetLeft = (it.canvasContainer?.offsetLeft || 0);
            let canvasOffsetTop = (it.canvasContainer?.offsetTop || 0);
            if (it.collect) {
                rt = new Rect(xMin - canvasOffsetLeft, Math.min(this.startY2, this.endY2) - it.offsetTop, xMax - xMin, Math.abs(this.startY2 - this.endY2));
            } else {
                rt = new Rect(xMin - canvasOffsetLeft, yMin - canvasOffsetTop + scrollTop + this.rowsEL!.offsetTop, xMax - xMin, yMax - yMin);
            }
            if (Rect.intersect(it.frame, rt)) {
                if (!rangeSelect) {
                    rangeSelect = new RangeSelectStruct();
                    let startX = Math.floor(rt.x <= 0 ? 0 : rt.x);
                    let endX = Math.floor((rt.x + rt.width) > it.frame.width ? it.frame.width : (rt.x + rt.width));
                    rangeSelect.startX = startX;
                    rangeSelect.endX = endX;
                    rangeSelect.startNS = Math.floor((TraceRow.range!.endNS - TraceRow.range!.startNS) * startX / it.frame.width + TraceRow.range!.startNS!);
                    rangeSelect.endNS = Math.floor((TraceRow.range!.endNS - TraceRow.range!.startNS) * endX / it.frame.width + TraceRow.range!.startNS!);
                }
                TraceRow.rangeSelectObject = rangeSelect;
                it.rangeSelect = true;
                return true
            } else {
                it.rangeSelect = false;
                return false;
            }
        })
        this.timerShaftEL!.sportRuler!.isRangeSelect = (this.rangeTraceRow?.length || 0) > 0;
        this.timerShaftEL!.sportRuler!.draw();
    }
}
