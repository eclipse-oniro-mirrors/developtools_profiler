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
    queryAbilityExits,
    queryBytesInAbilityData,
    queryBytesOutAbilityData,
    queryBytesReadAbilityData,
    queryBytesWrittenAbilityData,
    queryCachedFilesAbilityData,
    queryCompressedAbilityData,
    queryCpuAbilityData,
    queryCPuAbilityMaxData,
    queryCpuAbilitySystemData,
    queryCpuAbilityUserData,
    queryDiskIoMaxData,
    queryMemoryMaxData,
    queryMemoryUsedAbilityData,
    queryNetWorkMaxData,
    queryPacketsInAbilityData, queryPacketsOutAbilityData,
    queryReadAbilityData,
    queryWrittenAbilityData
} from "../../database/SqlLite.js";
import {info} from "../../../log/Log.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {ProcessStruct} from "../../bean/ProcessStruct.js";
import {procedurePool} from "../../database/Procedure.js";
import {CpuAbilityMonitorStruct} from "../../bean/CpuAbilityMonitorStruct.js";
import {CpuStruct} from "../../bean/CpuStruct.js";
import {MemoryAbilityMonitorStruct} from "../../bean/MemoryAbilityMonitorStruct.js";
import {DiskAbilityMonitorStruct} from "../../bean/DiskAbilityMonitorStruct.js";
import {NetworkAbilityMonitorStruct} from "../../bean/NetworkAbilityMonitorStruct.js";
import {Utils} from "../trace/base/Utils.js";

export class SpAbilityMonitorChart {
    private trace: SpSystemTrace;
    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }
    memoryMath = (maxByte: number) => {
        let maxByteName = ""
        if (maxByte > 0) {
            maxByteName = Utils.getBinaryByteWithUnit(maxByte)
        }
        return maxByteName;
    }

    diskIOMath = (maxByte: number) => {
        let maxByteName = ""
        if (maxByte > 0) {
            maxByteName = maxByte + "KB/S"
        }
        return maxByteName;
    }

    networkMath = (maxValue: number) => {
        let maxByteName = ""
        if (maxValue > 0) {
            maxByteName = Utils.getBinaryByteWithUnit(maxValue)
        }
        return maxByteName;
    }

    async init(){
        let time = new Date().getTime();
        let result = await queryAbilityExits();
        info("Ability Monitor Exits Tables size is: ", result!.length)
        if (result.length <= 0) return;
        let processRow = this.initAbilityRow();
        if (this.hasTable(result, "trace_cpu_usage")) {
            await this.initCpuAbility(processRow);
        }
        if (this.hasTable(result, "sys_memory")) {
            await this.initMemoryAbility(processRow);
        }
        if (this.hasTable(result, "trace_diskio")) {
            await this.initDiskAbility(processRow);
        }
        if (this.hasTable(result, "trace_network")) {
            await this.initNetworkAbility(processRow);
        }
        let durTime = new Date().getTime() - time;
        info('The time to load the AbilityMonitor data is: ', durTime)
    }

    private hasTable(result: Array<any>, tableName: string) {
        return result.find((o) => {
            return o.event_name === tableName
        })
    }

    private initAbilityRow = () => {
        let processRow = new TraceRow<ProcessStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        processRow.rowId = `abilityMonitor`
        processRow.rowType = TraceRow.ROW_TYPE_MONITOR
        processRow.rowParentId = '';
        processRow.folder = true;
        processRow.name = 'Ability Monitor';
        processRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        processRow.selectChangeHandler = this.trace.selectChangeHandler;
        processRow.supplier = () => new Promise<Array<any>>((resolve) => resolve([]));
        processRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `monitorGroup`, {
                    list: processRow.must ? processRow.dataList : undefined,
                    offscreen: processRow.must ? processRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: processRow.dpr,
                    isHover: processRow.isHover,
                    hoverX: processRow.hoverX,
                    hoverY: processRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: processRow.canvasWidth,
                    canvasHeight: processRow.canvasHeight,
                    isRangeSelect: processRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    useCache: useCache,
                    lineColor: processRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: processRow.frame,
                }, processRow.must && processRow.args.isOffScreen ? processRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    processRow.must = false;
                }
            )
        }
        this.trace.rowsEL?.appendChild(processRow)
        return processRow;
    }

    private initCpuAbility = async (processRow: TraceRow<ProcessStruct>) => {
        let time = new Date().getTime();
        let cpuMaxData = await queryCPuAbilityMaxData();
        let hasTotal = false;
        let hasUserLoad = false;
        let hasSystemLoad = false;
        let userLoad = cpuMaxData[0].userLoad;
        if (userLoad > 0) {
            hasUserLoad = true;
        }
        let systemLoad = cpuMaxData[0].systemLoad;
        if (systemLoad > 0) {
            hasSystemLoad = true;
        }
        let totalLoad = cpuMaxData[0].totalLoad;
        if (totalLoad > 0) {
            hasTotal = true;
        }
        let cpuNameList: Array<string> = ['Total', 'User', 'System']
        let traceRow = new TraceRow<CpuAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        traceRow.rowParentId = `abilityMonitor`
        traceRow.rowHidden = !processRow.expansion
        traceRow.rowId = cpuNameList[0]
        traceRow.rowType = TraceRow.ROW_TYPE_CPU_ABILITY
        traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        traceRow.selectChangeHandler = this.trace.selectChangeHandler;
        traceRow.style.height = '40px'
        traceRow.style.width = `100%`;
        traceRow.setAttribute('children', '');
        traceRow.name = `CPU ${cpuNameList[0]} Load`;
        traceRow.supplier = () => queryCpuAbilityData()
        traceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `monitorCpu0`, {
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
                    hoverCpuAbilityStruct: CpuAbilityMonitorStruct.hoverCpuAbilityStruct,
                    selectCpuAbilityStruct: CpuAbilityMonitorStruct.selectCpuAbilityStruct,
                    isRangeSelect: traceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxCpuUtilization: 100,
                    maxCpuUtilizationName: hasTotal ? "100%" : '0%',
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
                            CpuAbilityMonitorStruct.hoverCpuAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_CPU_ABILITY && it.name !== traceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(traceRow)

        let userTraceRow = new TraceRow<CpuAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        userTraceRow.rowParentId = `abilityMonitor`
        userTraceRow.rowHidden = !processRow.expansion
        userTraceRow.rowId = cpuNameList[1]
        userTraceRow.rowType = TraceRow.ROW_TYPE_CPU_ABILITY
        userTraceRow.style.height = '40px'
        userTraceRow.style.width = `100%`;
        userTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        userTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        userTraceRow.setAttribute('children', '');
        userTraceRow.name = `CPU ${cpuNameList[1]} Load`;
        userTraceRow.supplier = () => queryCpuAbilityUserData()
        userTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu1`, `monitorCpu1`, {
                    list: userTraceRow.must ? userTraceRow.dataList : undefined,
                    offscreen: userTraceRow.must ? userTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: userTraceRow.dpr,
                    isHover: userTraceRow.isHover,
                    hoverX: userTraceRow.hoverX,
                    hoverY: userTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: userTraceRow.canvasWidth,
                    canvasHeight: userTraceRow.canvasHeight,
                    hoverCpuAbilityStruct: CpuAbilityMonitorStruct.hoverCpuAbilityStruct,
                    selectCpuAbilityStruct: CpuAbilityMonitorStruct.selectCpuAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: userTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxCpuUtilization: 100,
                    maxCpuUtilizationName: hasUserLoad ? "100%" : '0%',
                    useCache: useCache,
                    lineColor: userTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: userTraceRow.frame,
                    isAbilityRow: true,
                    isStartAbilityRow: true,
                    isEndAbilityRow: false,
                }, userTraceRow.must && userTraceRow.args.isOffScreen ? userTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    userTraceRow.must = false;
                    if (userTraceRow.args.isOffScreen == true) {
                        if (userTraceRow.isHover) {
                            CpuAbilityMonitorStruct.hoverCpuAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_CPU_ABILITY && it.name !== userTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(userTraceRow)

        let sysTraceRow = new TraceRow<CpuAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        sysTraceRow.rowParentId = `abilityMonitor`
        sysTraceRow.rowHidden = !processRow.expansion
        sysTraceRow.rowId = cpuNameList[2]
        sysTraceRow.rowType = TraceRow.ROW_TYPE_CPU_ABILITY
        sysTraceRow.style.height = '40px'
        sysTraceRow.style.width = `100%`;
        sysTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        sysTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        sysTraceRow.setAttribute('children', '');
        sysTraceRow.name = `CPU ${cpuNameList[2]} Load`;
        sysTraceRow.supplier = () => queryCpuAbilitySystemData()
        sysTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu2`, `monitorCpu2`, {
                    list: sysTraceRow.must ? sysTraceRow.dataList : undefined,
                    offscreen: sysTraceRow.must ? sysTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: sysTraceRow.dpr,
                    isHover: sysTraceRow.isHover,
                    hoverX: sysTraceRow.hoverX,
                    hoverY: sysTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: sysTraceRow.canvasWidth,
                    canvasHeight: sysTraceRow.canvasHeight,
                    hoverCpuAbilityStruct: CpuAbilityMonitorStruct.hoverCpuAbilityStruct,
                    selectCpuAbilityStruct: CpuAbilityMonitorStruct.selectCpuAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: sysTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxCpuUtilization: 100,
                    maxCpuUtilizationName: hasSystemLoad ? "100%" : '0%',
                    useCache: useCache,
                    lineColor: sysTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: sysTraceRow.frame,
                    isAbilityRow: true,
                    isStartAbilityRow: true,
                    isEndAbilityRow: false,
                }, sysTraceRow.must && sysTraceRow.args.isOffScreen ? sysTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    sysTraceRow.must = false;
                    if (sysTraceRow.args.isOffScreen == true) {
                        if (sysTraceRow.isHover) {
                            CpuAbilityMonitorStruct.hoverCpuAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_CPU_ABILITY && it.name !== sysTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(sysTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the Ability Cpu is: ', durTime)
    }

    private initMemoryAbility = async (processRow: TraceRow<ProcessStruct>) => {
        let time = new Date().getTime();
        // sys.mem.total  sys.mem.cached  sys.mem.swap.total
        let memoryNameList: Array<string> = ['MemoryTotal', 'Cached', 'SwapTotal']
        let memoryTotal = await queryMemoryMaxData("sys.mem.total");
        let memoryTotalValue = memoryTotal[0].maxValue
        let memoryTotalId = memoryTotal[0].filter_id

        let memoryTotalValueName = this.memoryMath(memoryTotalValue);
        let memoryUsedTraceRow = new TraceRow<MemoryAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        memoryUsedTraceRow.rowParentId = `abilityMonitor`
        memoryUsedTraceRow.rowHidden = !processRow.expansion
        memoryUsedTraceRow.rowId = memoryNameList[0]
        memoryUsedTraceRow.rowType = TraceRow.ROW_TYPE_MEMORY_ABILITY
        memoryUsedTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        memoryUsedTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        memoryUsedTraceRow.style.height = '40px'
        memoryUsedTraceRow.style.width = `100%`;
        memoryUsedTraceRow.setAttribute('children', '');
        memoryUsedTraceRow.name = memoryNameList[0];
        memoryUsedTraceRow.supplier = () => queryMemoryUsedAbilityData(memoryTotalId)
        memoryUsedTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `monitorMemory0`, {
                    list: memoryUsedTraceRow.must ? memoryUsedTraceRow.dataList : undefined,
                    offscreen: memoryUsedTraceRow.must ? memoryUsedTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: memoryUsedTraceRow.dpr,
                    isHover: memoryUsedTraceRow.isHover,
                    hoverX: memoryUsedTraceRow.hoverX,
                    hoverY: memoryUsedTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: memoryUsedTraceRow.canvasWidth,
                    canvasHeight: memoryUsedTraceRow.canvasHeight,
                    hoverMemoryAbilityStruct: MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct,
                    selectMemoryAbilityStruct: MemoryAbilityMonitorStruct.selectMemoryAbilityStruct,
                    isRangeSelect: memoryUsedTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxMemoryByte: memoryTotalValue,
                    maxMemoryByteName: memoryTotalValueName,
                    useCache: useCache,
                    lineColor: memoryUsedTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: memoryUsedTraceRow.frame,
                }, memoryUsedTraceRow.must && memoryUsedTraceRow.args.isOffScreen ? memoryUsedTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    memoryUsedTraceRow.must = false;
                    if (memoryUsedTraceRow.args.isOffScreen == true) {
                        if (memoryUsedTraceRow.isHover) {
                            MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_MEMORY_ABILITY && it.name !== memoryUsedTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(memoryUsedTraceRow)

        let cached = await queryMemoryMaxData("sys.mem.cached");
        let cachedValue = cached[0].maxValue
        let cachedValueName = this.memoryMath(cachedValue);
        let cachedId = cached[0].filter_id

        let cachedFilesTraceRow = new TraceRow<MemoryAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        cachedFilesTraceRow.rowParentId = `abilityMonitor`
        cachedFilesTraceRow.rowHidden = !processRow.expansion
        cachedFilesTraceRow.rowId = memoryNameList[1]
        cachedFilesTraceRow.rowType = TraceRow.ROW_TYPE_MEMORY_ABILITY
        cachedFilesTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        cachedFilesTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        cachedFilesTraceRow.style.height = '40px'
        cachedFilesTraceRow.style.width = `100%`;
        cachedFilesTraceRow.setAttribute('children', '');
        cachedFilesTraceRow.name = memoryNameList[1];
        cachedFilesTraceRow.supplier = () => queryCachedFilesAbilityData(cachedId)
        cachedFilesTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu1`, `monitorMemory1`, {
                    list: cachedFilesTraceRow.must ? cachedFilesTraceRow.dataList : undefined,
                    offscreen: cachedFilesTraceRow.must ? cachedFilesTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: cachedFilesTraceRow.dpr,
                    isHover: cachedFilesTraceRow.isHover,
                    hoverX: cachedFilesTraceRow.hoverX,
                    hoverY: cachedFilesTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: cachedFilesTraceRow.canvasWidth,
                    canvasHeight: cachedFilesTraceRow.canvasHeight,
                    hoverMemoryAbilityStruct: MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct,
                    selectMemoryAbilityStruct: MemoryAbilityMonitorStruct.selectMemoryAbilityStruct,
                    isRangeSelect: cachedFilesTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxMemoryByte: cachedValue,
                    maxMemoryByteName: cachedValueName,
                    useCache: useCache,
                    lineColor: cachedFilesTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: cachedFilesTraceRow.frame,
                }, cachedFilesTraceRow.must && cachedFilesTraceRow.args.isOffScreen ? cachedFilesTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    cachedFilesTraceRow.must = false;
                    if (cachedFilesTraceRow.args.isOffScreen == true) {
                        if (cachedFilesTraceRow.isHover) {
                            MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_MEMORY_ABILITY && it.name !== cachedFilesTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(cachedFilesTraceRow)


        let swap = await queryMemoryMaxData("sys.mem.swap.total");
        let swapValue = swap[0].maxValue
        let swapValueName = this.memoryMath(swapValue);
        let swapId = swap[0].filter_id

        let compressedTraceRow = new TraceRow<MemoryAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        compressedTraceRow.rowParentId = `abilityMonitor`
        compressedTraceRow.rowHidden = !processRow.expansion
        compressedTraceRow.rowId = memoryNameList[2]
        compressedTraceRow.rowType = TraceRow.ROW_TYPE_MEMORY_ABILITY
        compressedTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        compressedTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        compressedTraceRow.style.height = '40px'
        compressedTraceRow.style.width = `100%`;
        compressedTraceRow.setAttribute('children', '');
        compressedTraceRow.name = memoryNameList[2];
        compressedTraceRow.supplier = () => queryCompressedAbilityData(swapId)
        compressedTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu2`, `monitorMemory2`, {
                    list: compressedTraceRow.must ? compressedTraceRow.dataList : undefined,
                    offscreen: compressedTraceRow.must ? compressedTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: compressedTraceRow.dpr,
                    isHover: compressedTraceRow.isHover,
                    hoverX: compressedTraceRow.hoverX,
                    hoverY: compressedTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: compressedTraceRow.canvasWidth,
                    canvasHeight: compressedTraceRow.canvasHeight,
                    hoverMemoryAbilityStruct: MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct,
                    selectMemoryAbilityStruct: MemoryAbilityMonitorStruct.selectMemoryAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: compressedTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxMemoryByte: swapValue,
                    maxMemoryByteName: swapValueName,
                    useCache: useCache,
                    lineColor: compressedTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: compressedTraceRow.frame,
                }, compressedTraceRow.must && compressedTraceRow.args.isOffScreen ? compressedTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    compressedTraceRow.must = false;
                    if (compressedTraceRow.args.isOffScreen == true) {
                        if (compressedTraceRow.isHover) {
                            MemoryAbilityMonitorStruct.hoverMemoryAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_MEMORY_ABILITY && it.name !== compressedTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(compressedTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the Ability Memory is: ', durTime)
    }

    private initDiskAbility = async (processRow: TraceRow<ProcessStruct>) => {
        let time = new Date().getTime();
        let maxList = await queryDiskIoMaxData();
        let maxBytesRead = maxList[0].bytesRead;
        let maxBytesReadName = this.diskIOMath(maxBytesRead);
        let diskIONameList: Array<string> = ['Bytes Read/Sec', 'Bytes Written/Sec', 'Read Ops/Sec', 'Written Ops/Sec']
        let bytesReadTraceRow = new TraceRow<DiskAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        bytesReadTraceRow.rowParentId = `abilityMonitor`
        bytesReadTraceRow.rowHidden = !processRow.expansion
        bytesReadTraceRow.rowId = diskIONameList[0]
        bytesReadTraceRow.rowType = TraceRow.ROW_TYPE_DISK_ABILITY
        bytesReadTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        bytesReadTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        bytesReadTraceRow.style.height = '40px'
        bytesReadTraceRow.style.width = `100%`;
        bytesReadTraceRow.setAttribute('children', '');
        bytesReadTraceRow.name = 'Disk ' + diskIONameList[0];
        bytesReadTraceRow.supplier = () => queryBytesReadAbilityData()
        bytesReadTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `monitorDiskIo0`, {
                    list: bytesReadTraceRow.must ? bytesReadTraceRow.dataList : undefined,
                    offscreen: bytesReadTraceRow.must ? bytesReadTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: bytesReadTraceRow.dpr,
                    isHover: bytesReadTraceRow.isHover,
                    hoverX: bytesReadTraceRow.hoverX,
                    hoverY: bytesReadTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: bytesReadTraceRow.canvasWidth,
                    canvasHeight: bytesReadTraceRow.canvasHeight,
                    hoverDiskAbilityStruct: DiskAbilityMonitorStruct.hoverDiskAbilityStruct,
                    selectDiskAbilityStruct: DiskAbilityMonitorStruct.selectDiskAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: bytesReadTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxDiskRate: maxBytesRead,
                    maxDiskRateName: maxBytesReadName,
                    useCache: useCache,
                    lineColor: bytesReadTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: bytesReadTraceRow.frame,
                }, bytesReadTraceRow.must && bytesReadTraceRow.args.isOffScreen ? bytesReadTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    bytesReadTraceRow.must = false;
                    if (bytesReadTraceRow.args.isOffScreen == true) {
                        if (bytesReadTraceRow.isHover) {
                            DiskAbilityMonitorStruct.hoverDiskAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_DISK_ABILITY && it.name !== bytesReadTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(bytesReadTraceRow)

        let maxBytesWrite = maxList[0].bytesWrite;
        let maxBytesWriteName = this.diskIOMath(maxBytesWrite);
        let bytesWrittenTraceRow = new TraceRow<DiskAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        bytesWrittenTraceRow.rowParentId = `abilityMonitor`
        bytesWrittenTraceRow.rowHidden = !processRow.expansion
        bytesWrittenTraceRow.rowId = diskIONameList[1]
        bytesWrittenTraceRow.rowType = TraceRow.ROW_TYPE_DISK_ABILITY
        bytesWrittenTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        bytesWrittenTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        bytesWrittenTraceRow.style.height = '40px'
        bytesWrittenTraceRow.style.width = `100%`;
        bytesWrittenTraceRow.setAttribute('children', '');
        bytesWrittenTraceRow.name = 'Disk ' + diskIONameList[1];
        bytesWrittenTraceRow.supplier = () => queryBytesWrittenAbilityData()
        bytesWrittenTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu1`, `monitorDiskIo1`, {
                    list: bytesWrittenTraceRow.must ? bytesWrittenTraceRow.dataList : undefined,
                    offscreen: bytesWrittenTraceRow.must ? bytesWrittenTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: bytesWrittenTraceRow.dpr,
                    isHover: bytesWrittenTraceRow.isHover,
                    hoverX: bytesWrittenTraceRow.hoverX,
                    hoverY: bytesWrittenTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: bytesWrittenTraceRow.canvasWidth,
                    canvasHeight: bytesWrittenTraceRow.canvasHeight,
                    hoverDiskAbilityStruct: DiskAbilityMonitorStruct.hoverDiskAbilityStruct,
                    selectDiskAbilityStruct: DiskAbilityMonitorStruct.selectDiskAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: bytesWrittenTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxDiskRate: maxBytesWrite,
                    maxDiskRateName: maxBytesWriteName,
                    useCache: useCache,
                    lineColor: bytesWrittenTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: bytesWrittenTraceRow.frame,
                }, bytesWrittenTraceRow.must && bytesWrittenTraceRow.args.isOffScreen ? bytesWrittenTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    bytesWrittenTraceRow.must = false;
                    if (bytesWrittenTraceRow.args.isOffScreen == true) {
                        if (bytesWrittenTraceRow.isHover) {
                            DiskAbilityMonitorStruct.hoverDiskAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_DISK_ABILITY && it.name !== bytesWrittenTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(bytesWrittenTraceRow)


        let maxReadOps = maxList[0].readOps;
        let maxReadOpsName = this.diskIOMath(maxReadOps);
        let readOpsTraceRow = new TraceRow<DiskAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        readOpsTraceRow.rowParentId = `abilityMonitor`
        readOpsTraceRow.rowHidden = !processRow.expansion
        readOpsTraceRow.rowId = diskIONameList[2]
        readOpsTraceRow.rowType = TraceRow.ROW_TYPE_DISK_ABILITY
        readOpsTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        readOpsTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        readOpsTraceRow.style.height = '40px'
        readOpsTraceRow.style.width = `100%`;
        readOpsTraceRow.setAttribute('children', '');
        readOpsTraceRow.name = 'Disk ' + diskIONameList[2];
        readOpsTraceRow.supplier = () => queryReadAbilityData()
        readOpsTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu2`, `monitorDiskIo2`, {
                    list: readOpsTraceRow.must ? readOpsTraceRow.dataList : undefined,
                    offscreen: readOpsTraceRow.must ? readOpsTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: readOpsTraceRow.dpr,
                    isHover: readOpsTraceRow.isHover,
                    hoverX: readOpsTraceRow.hoverX,
                    hoverY: readOpsTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: readOpsTraceRow.canvasWidth,
                    canvasHeight: readOpsTraceRow.canvasHeight,
                    hoverDiskAbilityStruct: DiskAbilityMonitorStruct.hoverDiskAbilityStruct,
                    selectDiskAbilityStruct: DiskAbilityMonitorStruct.selectDiskAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: readOpsTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxDiskRate: maxReadOps,
                    maxDiskRateName: maxReadOpsName,
                    useCache: useCache,
                    lineColor: readOpsTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: readOpsTraceRow.frame,
                }, readOpsTraceRow.must && readOpsTraceRow.args.isOffScreen ? readOpsTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    readOpsTraceRow.must = false;
                    if (readOpsTraceRow.args.isOffScreen == true) {
                        if (readOpsTraceRow.isHover) {
                            DiskAbilityMonitorStruct.hoverDiskAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_DISK_ABILITY && it.name !== readOpsTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(readOpsTraceRow)

        let maxWriteOps = maxList[0].writeOps;
        let maxWriteOpsName = this.diskIOMath(maxWriteOps);
        let writtenOpsTraceRow = new TraceRow<DiskAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        writtenOpsTraceRow.rowParentId = `abilityMonitor`
        writtenOpsTraceRow.rowHidden = !processRow.expansion
        writtenOpsTraceRow.rowId = diskIONameList[3]
        writtenOpsTraceRow.rowType = TraceRow.ROW_TYPE_DISK_ABILITY
        writtenOpsTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        writtenOpsTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        writtenOpsTraceRow.style.height = '40px'
        writtenOpsTraceRow.style.width = `100%`;
        writtenOpsTraceRow.setAttribute('children', '');
        writtenOpsTraceRow.name = 'Disk ' + diskIONameList[3];
        writtenOpsTraceRow.supplier = () => queryWrittenAbilityData()
        writtenOpsTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu3`, `monitorDiskIo3`, {
                    list: writtenOpsTraceRow.must ? writtenOpsTraceRow.dataList : undefined,
                    offscreen: writtenOpsTraceRow.must ? writtenOpsTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: writtenOpsTraceRow.dpr,
                    isHover: writtenOpsTraceRow.isHover,
                    hoverX: writtenOpsTraceRow.hoverX,
                    hoverY: writtenOpsTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: writtenOpsTraceRow.canvasWidth,
                    canvasHeight: writtenOpsTraceRow.canvasHeight,
                    hoverDiskAbilityStruct: DiskAbilityMonitorStruct.hoverDiskAbilityStruct,
                    selectDiskAbilityStruct: DiskAbilityMonitorStruct.selectDiskAbilityStruct,
                    wakeupBean: CpuStruct.wakeupBean,
                    isRangeSelect: writtenOpsTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxDiskRate: maxWriteOps,
                    maxDiskRateName: maxWriteOpsName,
                    useCache: useCache,
                    lineColor: writtenOpsTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: writtenOpsTraceRow.frame,
                }, writtenOpsTraceRow.must && writtenOpsTraceRow.args.isOffScreen ? writtenOpsTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    writtenOpsTraceRow.must = false;
                    if (writtenOpsTraceRow.args.isOffScreen == true) {
                        if (writtenOpsTraceRow.isHover) {
                            DiskAbilityMonitorStruct.hoverDiskAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_DISK_ABILITY && it.name !== writtenOpsTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(writtenOpsTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the Ability DiskIO is: ', durTime)
    }

    private initNetworkAbility = async (processRow: TraceRow<ProcessStruct>) => {
        let time = new Date().getTime();
        let maxList = await queryNetWorkMaxData();
        let maxBytesIn = maxList[0].maxIn;
        let maxInByteName = this.networkMath(maxBytesIn);
        let networkNameList: Array<string> = ['Bytes In/Sec', 'Bytes Out/Sec', 'Packets In/Sec', 'Packets Out/Sec']
        let bytesInTraceRow = new TraceRow<NetworkAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        bytesInTraceRow.rowParentId = `abilityMonitor`
        bytesInTraceRow.rowHidden = !processRow.expansion
        bytesInTraceRow.rowId = networkNameList[0]
        bytesInTraceRow.rowType = TraceRow.ROW_TYPE_NETWORK_ABILITY
        bytesInTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        bytesInTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        bytesInTraceRow.style.height = '40px'
        bytesInTraceRow.style.width = `100%`;
        bytesInTraceRow.setAttribute('children', '');
        bytesInTraceRow.name = 'Network ' + networkNameList[0];
        bytesInTraceRow.supplier = () => queryBytesInAbilityData()
        bytesInTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `monitorNetwork0`, {
                    list: bytesInTraceRow.must ? bytesInTraceRow.dataList : undefined,
                    offscreen: bytesInTraceRow.must ? bytesInTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: bytesInTraceRow.dpr,
                    isHover: bytesInTraceRow.isHover,
                    hoverX: bytesInTraceRow.hoverX,
                    hoverY: bytesInTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: bytesInTraceRow.canvasWidth,
                    canvasHeight: bytesInTraceRow.canvasHeight,
                    hoverNetworkAbilityStruct: NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct,
                    selectNetworkAbilityStruct: NetworkAbilityMonitorStruct.selectNetworkAbilityStruct,
                    isRangeSelect: bytesInTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxNetworkRate: maxBytesIn,
                    maxNetworkRateName: maxInByteName,
                    useCache: useCache,
                    lineColor: bytesInTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: bytesInTraceRow.frame,
                }, bytesInTraceRow.must && bytesInTraceRow.args.isOffScreen ? bytesInTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    bytesInTraceRow.must = false;
                    if (bytesInTraceRow.args.isOffScreen == true) {
                        if (bytesInTraceRow.isHover) {
                            NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_NETWORK_ABILITY && it.name !== bytesInTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(bytesInTraceRow)

        let bytesOutTraceRow = new TraceRow<NetworkAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        let maxBytesOut = maxList[0].maxOut;
        let maxOutByteName = this.networkMath(maxBytesOut);
        bytesOutTraceRow.rowParentId = `abilityMonitor`
        bytesOutTraceRow.rowHidden = !processRow.expansion
        bytesOutTraceRow.rowId = networkNameList[1]
        bytesOutTraceRow.rowType = TraceRow.ROW_TYPE_NETWORK_ABILITY
        bytesOutTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        bytesOutTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        bytesOutTraceRow.style.height = '40px'
        bytesOutTraceRow.style.width = `100%`;
        bytesOutTraceRow.setAttribute('children', '');
        bytesOutTraceRow.name = 'Network ' + networkNameList[1];
        bytesOutTraceRow.supplier = () => queryBytesOutAbilityData();
        bytesOutTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu1`, `monitorNetwork1`, {
                    list: bytesOutTraceRow.must ? bytesOutTraceRow.dataList : undefined,
                    offscreen: bytesOutTraceRow.must ? bytesOutTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: bytesOutTraceRow.dpr,
                    isHover: bytesOutTraceRow.isHover,
                    hoverX: bytesOutTraceRow.hoverX,
                    hoverY: bytesOutTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: bytesOutTraceRow.canvasWidth,
                    canvasHeight: bytesOutTraceRow.canvasHeight,
                    hoverNetworkAbilityStruct: NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct,
                    selectNetworkAbilityStruct: NetworkAbilityMonitorStruct.selectNetworkAbilityStruct,
                    isRangeSelect: bytesOutTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxNetworkRate: maxBytesOut,
                    maxNetworkRateName: maxOutByteName,
                    useCache: useCache,
                    lineColor: bytesOutTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: bytesOutTraceRow.frame,
                }, bytesOutTraceRow.must && bytesOutTraceRow.args.isOffScreen ? bytesOutTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    bytesOutTraceRow.must = false;
                    if (bytesOutTraceRow.args.isOffScreen == true) {
                        if (bytesOutTraceRow.isHover) {
                            NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_NETWORK_ABILITY && it.name !== bytesOutTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(bytesOutTraceRow)


        let packetInTraceRow = new TraceRow<NetworkAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        let maxPacketIn = maxList[0].maxPacketIn;
        let maxInPacketName = this.networkMath(maxPacketIn);
        packetInTraceRow.rowParentId = `abilityMonitor`
        packetInTraceRow.rowHidden = !processRow.expansion
        packetInTraceRow.rowId = networkNameList[2]
        packetInTraceRow.rowType = TraceRow.ROW_TYPE_NETWORK_ABILITY
        packetInTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        packetInTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        packetInTraceRow.style.height = '40px'
        packetInTraceRow.style.width = `100%`;
        packetInTraceRow.setAttribute('children', '');
        packetInTraceRow.name = 'Network ' + networkNameList[2];
        packetInTraceRow.supplier = () => queryPacketsInAbilityData();
        packetInTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu2`, `monitorNetwork-Packet2`, {
                    list: packetInTraceRow.must ? packetInTraceRow.dataList : undefined,
                    offscreen: packetInTraceRow.must ? packetInTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: packetInTraceRow.dpr,
                    isHover: packetInTraceRow.isHover,
                    hoverX: packetInTraceRow.hoverX,
                    hoverY: packetInTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: packetInTraceRow.canvasWidth,
                    canvasHeight: packetInTraceRow.canvasHeight,
                    hoverNetworkAbilityStruct: NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct,
                    selectNetworkAbilityStruct: NetworkAbilityMonitorStruct.selectNetworkAbilityStruct,
                    isRangeSelect: packetInTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxNetworkRate: maxPacketIn,
                    maxNetworkRateName: maxInPacketName,
                    useCache: useCache,
                    lineColor: packetInTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: packetInTraceRow.frame,
                }, packetInTraceRow.must && packetInTraceRow.args.isOffScreen ? packetInTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    packetInTraceRow.must = false;
                    if (packetInTraceRow.args.isOffScreen == true) {
                        if (packetInTraceRow.isHover) {
                            NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_NETWORK_ABILITY && it.name !== packetInTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(packetInTraceRow)


        let packetOutTraceRow = new TraceRow<NetworkAbilityMonitorStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        let maxPacketOut = maxList[0].maxPacketOut;
        let maxOutPacketName = this.networkMath(maxPacketOut);
        packetOutTraceRow.rowParentId = `abilityMonitor`
        packetOutTraceRow.rowHidden = !processRow.expansion
        packetOutTraceRow.rowId = networkNameList[3]
        packetOutTraceRow.rowType = TraceRow.ROW_TYPE_NETWORK_ABILITY
        packetOutTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        packetOutTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        packetOutTraceRow.style.height = '40px'
        packetOutTraceRow.style.width = `100%`;
        packetOutTraceRow.setAttribute('children', '');
        packetOutTraceRow.name = 'Network ' + networkNameList[3];
        packetOutTraceRow.supplier = () => queryPacketsOutAbilityData();
        packetOutTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu3`, `monitorNetwork3`, {
                    list: packetOutTraceRow.must ? packetOutTraceRow.dataList : undefined,
                    offscreen: packetOutTraceRow.must ? packetOutTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: packetOutTraceRow.dpr,
                    isHover: packetOutTraceRow.isHover,
                    hoverX: packetOutTraceRow.hoverX,
                    hoverY: packetOutTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: packetOutTraceRow.canvasWidth,
                    canvasHeight: packetOutTraceRow.canvasHeight,
                    hoverNetworkAbilityStruct: NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct,
                    selectNetworkAbilityStruct: NetworkAbilityMonitorStruct.selectNetworkAbilityStruct,
                    isRangeSelect: packetOutTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxNetworkRate: maxPacketOut,
                    maxNetworkRateName: maxOutPacketName,
                    useCache: useCache,
                    lineColor: packetOutTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: packetOutTraceRow.frame,
                }, packetOutTraceRow.must && packetOutTraceRow.args.isOffScreen ? packetOutTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    packetOutTraceRow.must = false;
                    if (packetOutTraceRow.args.isOffScreen == true) {
                        if (packetOutTraceRow.isHover) {
                            NetworkAbilityMonitorStruct.hoverNetworkAbilityStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_NETWORK_ABILITY && it.name !== packetOutTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(packetOutTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the Ability Network is: ', durTime)
    }
}