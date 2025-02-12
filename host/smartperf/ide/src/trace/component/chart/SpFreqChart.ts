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
import {
    getCpuLimitFreq,
    getCpuLimitFreqId, getCpuLimitFreqMax,
    queryCpuFreq,
    queryCpuFreqData,
    queryCpuMaxFreq,
    queryCpuState,
    queryCpuStateFilter
} from "../../database/SqlLite.js";
import {info} from "../../../log/Log.js";
import {CpuFreqStruct} from "../../bean/CpuFreqStruct.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {procedurePool} from "../../database/Procedure.js";
import {CpuStruct} from "../../bean/CpuStruct.js";
import { ColorUtils } from "../trace/base/ColorUtils.js";
import {CpuFreqLimitsStruct} from "../../database/ui-worker/ProcedureWorkerCpuFreqLimits.js";

export class SpFreqChart {
    private trace: SpSystemTrace;
    static hoverStateStruct:any;
    static selectStateStruct:any;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    async init() {
        let cpuFreqStartTime = new Date().getTime();
        let freqList = await queryCpuFreq();
        let cpuStateFilterIds = await queryCpuStateFilter();
        let cpuFreqLimits = await getCpuLimitFreqId()
        let cpuFreqLimitsMax = await getCpuLimitFreqMax(cpuFreqLimits.map((limit)=>{
            return limit.maxFilterId
        }).join(","))
        info("Cpu Freq data size is: ", freqList!.length)
        let freqMaxList = await queryCpuMaxFreq();
        CpuFreqStruct.maxFreq = freqMaxList[0].maxFreq;
        let maxFreqObj = this.math(freqMaxList[0].maxFreq);
        CpuFreqStruct.maxFreq = maxFreqObj.maxFreq;
        CpuFreqStruct.maxFreqName = maxFreqObj.maxFreqName;
        for (let i = 0; i < freqList.length; i++) {
            const it = freqList[i];
            let traceRow = new TraceRow<CpuFreqStruct>({
                canvasNumber: 1,
                alpha: true,
                contextId: '2d',
                isOffScreen: SpSystemTrace.isCanvasOffScreen
            });
            traceRow.rowId = `${it.filterId}`
            traceRow.rowType = TraceRow.ROW_TYPE_CPU_FREQ
            traceRow.rowParentId = ''
            traceRow.style.height = '40px'
            traceRow.name = `Cpu ${it.cpu} Frequency`;
            traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            traceRow.selectChangeHandler = this.trace.selectChangeHandler;
            traceRow.supplier = () => queryCpuFreqData(it.cpu)
            traceRow.onThreadHandler = (useCache) => {
                procedurePool.submitWithName(`freq${it.cpu % procedurePool.freqLen.length}`, `freq${it.cpu}`, {
                    list: traceRow.must ? traceRow.dataList : undefined,
                    offscreen: !traceRow.isTransferCanvas ? traceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: traceRow.dpr,
                    isHover: traceRow.isHover,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    hoverX: traceRow.hoverX,
                    hoverY: traceRow.hoverY,
                    canvasWidth: traceRow.canvasWidth,
                    canvasHeight: traceRow.canvasHeight,
                    hoverCpuFreqStruct: CpuFreqStruct.hoverCpuFreqStruct,
                    selectCpuFreqStruct: CpuFreqStruct.selectCpuFreqStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: traceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxFreq: CpuFreqStruct.maxFreq,
                    maxFreqName: CpuFreqStruct.maxFreqName,
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
                    if (traceRow.args.isOffScreen == true) {
                        if (traceRow.isHover) {
                            CpuFreqStruct.hoverCpuFreqStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_CPU_FREQ && it.name !== traceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                })
                traceRow.isTransferCanvas = true;
            }
            this.trace.rowsEL?.appendChild(traceRow)
        }
        for (let it of cpuStateFilterIds) {
            let cpuStateRow = new TraceRow();
            cpuStateRow.rowId = `${cpuStateFilterIds[it.cpu].filterId}`
            cpuStateRow.rowType = TraceRow.ROW_TYPE_CPU_STATE
            cpuStateRow.rowParentId = ''
            cpuStateRow.style.height = '40px'
            cpuStateRow.name = `Cpu ${it.cpu} State`
            cpuStateRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            cpuStateRow.selectChangeHandler = this.trace.selectChangeHandler;
            cpuStateRow.isHover = true;
            cpuStateRow.supplier = () => queryCpuState(cpuStateFilterIds[it.cpu].filterId);
            cpuStateRow.onThreadHandler = ((useCache: boolean) => {
                procedurePool.submitWithName(`process${it.cpu % procedurePool.cpusLen.length}`, `cpu-state-${it.cpu}`, cpuStateRow.buildArgs({
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    cpu:it.cpu,
                    useCache: useCache,
                    wakeupBean: CpuStruct.wakeupBean,
                    selectStateStruct:SpFreqChart.selectStateStruct,
                    lineColor: cpuStateRow.getLineColor(),
                    chartColor:ColorUtils.colorForTid(it.cpu),
                }), cpuStateRow.getTransferArray(), (res: any, hover: any) => {
                    cpuStateRow.must = false;
                    if (cpuStateRow.isHover) {
                        SpFreqChart.hoverStateStruct = hover;
                    }
                })
                cpuStateRow.isTransferCanvas = true;
            })
            this.trace.rowsEL?.appendChild(cpuStateRow);
        }
        let durTime = new Date().getTime() - cpuFreqStartTime;
        info('The time to load the CpuFreq data is: ', durTime)
        for(let limit of cpuFreqLimits){
            let findMax = this.math(cpuFreqLimitsMax.find((maxLimit)=>{
                return maxLimit.filterId == limit.maxFilterId
            })?.maxValue||0)
            let cpuFreqLimitRow = new TraceRow();
            cpuFreqLimitRow.rowId = `${limit.cpu}`
            cpuFreqLimitRow.rowType = TraceRow.ROW_TYPE_CPU_FREQ_LIMIT
            cpuFreqLimitRow.rowParentId = ''
            cpuFreqLimitRow.style.height = '40px'
            cpuFreqLimitRow.name = `Cpu ${limit.cpu} Freq Limit`
            cpuFreqLimitRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            cpuFreqLimitRow.selectChangeHandler = this.trace.selectChangeHandler;
            cpuFreqLimitRow.isHover = true;
            cpuFreqLimitRow.supplier = () => getCpuLimitFreq(limit.maxFilterId,limit.minFilterId,limit.cpu);
            cpuFreqLimitRow.onThreadHandler = ((useCache: boolean) => {
                procedurePool.submitWithName(`process${limit.cpu % procedurePool.cpusLen.length}`, `cpu-limit-freq-${limit.cpu}`, cpuFreqLimitRow.buildArgs({
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    wakeupBean: CpuStruct.wakeupBean,
                    cpu:limit.cpu,
                    useCache: useCache,
                    maxFreq: findMax?.maxFreq||0,
                    maxFreqName: findMax?.maxFreqName||"",
                    selectCpuFreqLimitsStruct:CpuFreqLimitsStruct.selectCpuFreqLimitsStruct,
                    hoverCpuFreqLimitsStruct:CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct,
                    lineColor: cpuFreqLimitRow.getLineColor(),
                    chartColor:ColorUtils.colorForTid(limit.cpu),
                }), cpuFreqLimitRow.getTransferArray(), (res: any, hover: any) => {
                    cpuFreqLimitRow.must = false;
                    if (cpuFreqLimitRow.isHover) {
                        CpuFreqLimitsStruct.hoverCpuFreqLimitsStruct = hover;
                    }
                })
                cpuFreqLimitRow.isTransferCanvas = true;
            })
            this.trace.rowsEL?.appendChild(cpuFreqLimitRow);
        }
    }

    math = (maxFreq:number) => {
        let maxFreqObj = {
            maxFreqName:" ",
            maxFreq:0
        }
        let units: Array<string> = ["", "K", "M", "G", "T", "E"];
        let sb = " ";
        if (maxFreq > 0) {
            let log10: number = Math.ceil(Math.log10(maxFreq));
            let pow10: number = Math.pow(10, log10);
            let afterCeil: number = Math.ceil(maxFreq / (pow10 / 4)) * (pow10 / 4);
            maxFreqObj.maxFreq = afterCeil;
            let unitIndex: number = Math.floor(log10 / 3);
            sb = `${afterCeil / Math.pow(10, unitIndex * 3)}${units[unitIndex + 1]}hz`
        }
        maxFreqObj.maxFreqName = sb.toString();
        return maxFreqObj;
    }
}

export class CpuFreqRowLimit {
    cpu: number = 0;
    maxFilterId: number = 0;
    minFilterId: number = 0;
}