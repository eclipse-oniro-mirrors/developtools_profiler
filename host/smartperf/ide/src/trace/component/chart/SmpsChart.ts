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

import {SpSystemTrace} from "../SpSystemTrace.js";
import {querySmapsData, querySmapsDataMax, querySmapsExits} from "../../database/SqlLite.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {BaseStruct} from "../../bean/BaseStruct.js";
import {procedurePool} from "../../database/Procedure.js";
import {CounterStruct} from "../../bean/SdkStruct.js";
import {SmapsShowStruct} from "../../bean/SmapsShowStruct.js";

export class SmpsChart {
    private trace: SpSystemTrace;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    async init() {
        let result = await querySmapsExits();
        if (result.length <= 0) return;
        let smapsRow = this.initSmapsRow();
        let rowNameList: Array<string> = ['Dirty Size', 'Swapped Size', 'Resident Size']
        for (let rowName of rowNameList) {
            await this.initRows(smapsRow, rowName);
        }
    }

    private initSmapsRow = () => {
        let smapsRow = new TraceRow<any>();
        smapsRow.rowId = `smapsRow`
        smapsRow.rowType = TraceRow.ROW_TYPE_SMAPS
        smapsRow.rowParentId = '';
        smapsRow.folder = true;
        smapsRow.name = 'VM Tracker';
        smapsRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        smapsRow.selectChangeHandler = this.trace.selectChangeHandler;
        smapsRow.supplier = () => new Promise<Array<any>>((resolve) => resolve([]));
        smapsRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `smaps`, {
                    list: smapsRow.must ? smapsRow.dataList : undefined,
                    offscreen: smapsRow.must ? smapsRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: smapsRow.dpr,
                    isHover: smapsRow.isHover,
                    hoverX: smapsRow.hoverX,
                    hoverY: smapsRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: smapsRow.canvasWidth,
                    canvasHeight: smapsRow.canvasHeight,
                    isRangeSelect: smapsRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    useCache: useCache,
                    lineColor: smapsRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: smapsRow.frame,
                }, smapsRow.must && smapsRow.args.isOffScreen ? smapsRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    smapsRow.must = false;
                }
            )
        }
        this.trace.rowsEL?.appendChild(smapsRow)
        return smapsRow;
    }

    private initRows = async (nodeRow: TraceRow<BaseStruct>, rowName:string ) => {
        let traceRow = new TraceRow<CounterStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        traceRow.rowParentId = `smapsRow`
        traceRow.rowHidden = !nodeRow.expansion
        traceRow.rowId = rowName
        traceRow.rowType = TraceRow.ROW_TYPE_SMAPS
        traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        traceRow.selectChangeHandler = this.trace.selectChangeHandler;
        traceRow.style.height = '40px'
        traceRow.style.width = `100%`;
        traceRow.setAttribute('children', '');
        traceRow.name = rowName;
        let columnName = ""
        if (rowName == "Dirty Size") {
            columnName = "dirty"
        } else if (rowName == "Swapped Size") {
            columnName = "swapper"
        } else {
            columnName = "resident_size"
        }
        traceRow.supplier = () => querySmapsData(columnName)
        let maxList = await querySmapsDataMax(columnName);
        let maxValue = maxList[0].max_value;
        traceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process0`, `smaps-${rowName}`, {
                    list: traceRow.must ? traceRow.dataList : undefined,
                    offscreen: traceRow.must ? traceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: traceRow.dpr,
                    isHover: traceRow.isHover,
                    hoverX: traceRow.hoverX,
                    hoverY: traceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: traceRow.canvasWidth,
                    canvasHeight: traceRow.canvasHeight,
                    hoverCounterStruct: SmapsShowStruct.hoverStruct,
                    selectCounterStruct: SmapsShowStruct.selectStruct,
                    isRangeSelect: traceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxValue: maxValue,
                    maxValueName: maxValue + "",
                    rowName: columnName,
                    useCache: useCache,
                    lineColor: traceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: traceRow.frame,
                }, traceRow.must && traceRow.args.isOffScreen ? traceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    traceRow.must = false;
                    if (traceRow.args.isOffScreen == true) {
                        if (traceRow.isHover) {
                            SmapsShowStruct.hoverStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_SMAPS && it.name !== traceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(traceRow)
    }
}