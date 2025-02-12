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
import {queryCpuData, queryCpuMax} from "../../database/SqlLite.js";
import {info} from "../../../log/Log.js";
import {CpuStruct} from "../../bean/CpuStruct.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {procedurePool} from "../../database/Procedure.js";

export class SpCpuChart {
    private trace: SpSystemTrace;
    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    async init() {
        let CpuStartTime = new Date().getTime();
        let array = await queryCpuMax();
        info("Cpu trace row data size is: ", array.length)
        if (array && array.length > 0 && array[0]) {
            let cpuMax = array[0].cpu
            CpuStruct.cpuCount = cpuMax + 1;
            for (let i1 = 0; i1 < CpuStruct.cpuCount; i1++) {
                const cpuId = i1;
                let traceRow = new TraceRow<CpuStruct>();
                traceRow.rowId = `${cpuId}`
                traceRow.rowType = TraceRow.ROW_TYPE_CPU
                traceRow.rowParentId = ''
                traceRow.style.height = '40px'
                traceRow.name = `Cpu ${cpuId}`
                traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
                traceRow.selectChangeHandler = this.trace.selectChangeHandler;
                traceRow.supplier = () => queryCpuData(cpuId, TraceRow.range?.startNS || 0, TraceRow.range?.endNS || 0)
                traceRow.onThreadHandler = ((useCache: boolean, buf: ArrayBuffer | undefined | null) => {
                    procedurePool.submitWithName(`cpu${cpuId % procedurePool.cpusLen.length}`, `cpu-data-${cpuId}`, {
                        list: traceRow.must ? traceRow.dataList : undefined,
                        offscreen: !traceRow.isTransferCanvas ? traceRow.offscreen[0] : undefined,//是否离屏
                        dpr: traceRow.dpr,//屏幕dpr值
                        xs: TraceRow.range?.xs,//线条坐标信息
                        isHover: traceRow.isHover,
                        flagMoveInfo: this.trace.hoverFlag,
                        flagSelectedInfo: this.trace.selectFlag,
                        hoverX: traceRow.hoverX,
                        hoverY: traceRow.hoverY,
                        canvasWidth: traceRow.canvasWidth,
                        canvasHeight: traceRow.canvasHeight,
                        hoverCpuStruct: CpuStruct.hoverCpuStruct,
                        selectCpuStruct: CpuStruct.selectCpuStruct,
                        wakeupBean: CpuStruct.wakeupBean,
                        isRangeSelect: traceRow.rangeSelect,
                        rangeSelectObject: TraceRow.rangeSelectObject,
                        useCache: useCache,
                        lineColor: traceRow.getLineColor(),
                        startNS: TraceRow.range?.startNS || 0,
                        endNS: TraceRow.range?.endNS || 0,
                        totalNS: TraceRow.range?.totalNS || 0,
                        slicesTime: TraceRow.range?.slicesTime,
                        range: TraceRow.range,
                        frame: traceRow.frame
                    }, traceRow.getTransferArray(), (res: any, hover: any) => {
                        traceRow.must = false;
                        if (traceRow.isHover) {
                            CpuStruct.hoverCpuStruct = hover;
                            if (TraceRow.range) TraceRow.range.refresh = false;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_CPU && it.name !== traceRow.name).forEach(it => it.draw(true));
                        }
                    })
                    traceRow.isTransferCanvas = true;
                })
                this.trace.rowsEL?.appendChild(traceRow);

            }
        }
        let CpuDurTime = new Date().getTime() - CpuStartTime;
        info('The time to load the Cpu data is: ', CpuDurTime)
    }

    initProcessThreadStateData = async (progress: Function) => {
        let time = new Date().getTime();
        SpSystemTrace.SPT_DATA = [];
        progress("StateProcessThread", 93);
        procedurePool.submitWithName("logic1","spt-init",{},undefined,(res:any)=>{
            SpSystemTrace.SPT_DATA = Array.from(res);
        })
        let durTime = new Date().getTime() - time;
        info('The time to load the first ProcessThreadState data is: ', durTime)
    }
}