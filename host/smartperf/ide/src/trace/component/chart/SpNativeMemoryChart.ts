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
import {query, queryAllHeapByEvent, queryHeapGroupByEvent, queryNativeHookProcess} from "../../database/SqlLite.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {info} from "../../../log/Log.js";
import {procedurePool} from "../../database/Procedure.js";
import {HeapStruct} from "../../bean/HeapStruct.js";
import {NativeEvent, NativeEventHeap} from "../../bean/NativeHook.js";

export class SpNativeMemoryChart {
    static EVENT_HEAP: Array<NativeEventHeap> = [];
    private trace: SpSystemTrace;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    initChart = async () => {
        let time = new Date().getTime();
        let nativeProcess = await queryNativeHookProcess();
        info("NativeHook Process data size is: ", nativeProcess!.length)
        if (nativeProcess.length == 0) {
            return;
        }
        SpNativeMemoryChart.EVENT_HEAP = await queryHeapGroupByEvent();
        let nativeRow = new TraceRow({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        let process = "";
        if (nativeProcess.length > 0) {
            process = ` ${nativeProcess[0].pid}`
        }
        nativeRow.rowId = `native-memory`
        nativeRow.index = 0;
        nativeRow.rowType = TraceRow.ROW_TYPE_NATIVE_MEMORY
        nativeRow.drawType = 0;
        nativeRow.rowParentId = '';
        nativeRow.folder = true;
        nativeRow.name = `Native Memory` + process;
        nativeRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        nativeRow.selectChangeHandler = this.trace.selectChangeHandler;
        nativeRow.onDrawTypeChangeHandler = (type) => {
            this.trace.rowsEL?.querySelectorAll<TraceRow<any>>(`trace-row[row-type='heap']`).forEach(it => {
                it.drawType = type;
                it.isComplete = false;
                it.draw();
            })
        };
        nativeRow.supplier = () => new Promise<Array<any>>((resolve, reject) => resolve([]));
        nativeRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${nativeRow.index}`, `native-memory`, {
                list: nativeRow.must ? nativeRow.dataList : undefined,
                offscreen: !nativeRow.isTransferCanvas ? nativeRow.offscreen[0] : undefined,
                xs: TraceRow.range?.xs,
                dpr: nativeRow.dpr,
                isHover: nativeRow.isHover,
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                hoverX: nativeRow.hoverX,
                hoverY: nativeRow.hoverY,
                canvasWidth: nativeRow.canvasWidth,
                canvasHeight: nativeRow.canvasHeight,
                isRangeSelect: nativeRow.rangeSelect,
                rangeSelectObject: TraceRow.rangeSelectObject,
                useCache: useCache,
                lineColor: nativeRow.getLineColor(),
                startNS: TraceRow.range?.startNS || 0,
                endNS: TraceRow.range?.endNS || 0,
                totalNS: TraceRow.range?.totalNS || 0,
                slicesTime: TraceRow.range?.slicesTime,
                range: TraceRow.range,
                frame: nativeRow.frame
            }, !nativeRow.isTransferCanvas ? nativeRow.offscreen[0] : undefined, (res: any) => {
                nativeRow.must = false;
            });
            nativeRow.isTransferCanvas = true;
        }

        this.trace.rowsEL?.appendChild(nativeRow)
        /**
         * 添加heap信息
         */
        let native_memory = ["All Heap & Anonymous VM", "All Heap", "All Anonymous VM"];
        for (let i = 0; i < native_memory.length; i++) {
            let nm = native_memory[i];
            let allHeapRow = new TraceRow<HeapStruct>({
                canvasNumber: 1,
                alpha: false,
                contextId: '2d',
                isOffScreen: true
            });
            allHeapRow.index = i;
            allHeapRow.rowParentId = `native-memory`
            allHeapRow.rowHidden = !nativeRow.expansion
            allHeapRow.style.height = '40px'
            allHeapRow.name = nm;
            allHeapRow.rowId = nm;
            allHeapRow.drawType = 0;
            allHeapRow.folder = false;
            allHeapRow.rowType = TraceRow.ROW_TYPE_HEAP;
            allHeapRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            allHeapRow.selectChangeHandler = this.trace.selectChangeHandler;
            allHeapRow.setAttribute('children', '')
            allHeapRow.supplier = () => {
                return this.getNativeMemoryDataByChartType(i, allHeapRow.drawType)
            }
            allHeapRow.onThreadHandler = (useCache) => {
                procedurePool.submitWithName(`process${allHeapRow.index}`, `heap-${nm}`, {
                    list: allHeapRow.must ? allHeapRow.dataList : undefined,
                    offscreen: !allHeapRow.isTransferCanvas ? allHeapRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: allHeapRow.dpr,
                    isHover: allHeapRow.isHover,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    hoverX: allHeapRow.hoverX,
                    hoverY: allHeapRow.hoverY,
                    canvasWidth: allHeapRow.canvasWidth,
                    canvasHeight: allHeapRow.canvasHeight,
                    isRangeSelect: allHeapRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    useCache: useCache,
                    lineColor: allHeapRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: allHeapRow.frame
                }, !allHeapRow.isTransferCanvas ? allHeapRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    allHeapRow.must = false;
                    if (allHeapRow.isHover) {
                        HeapStruct.hoverHeapStruct = hover;
                    }
                });
                allHeapRow.isTransferCanvas = true;
            }
            this.trace.rowsEL?.appendChild(allHeapRow)
        }
        let durTime = new Date().getTime() - time;
        info('The time to load the Native Memory data is: ', durTime)
    }

    getNativeMemoryDataByChartType = async (nativeMemoryType: number, chartType: number): Promise<Array<HeapStruct>> => {
        let args = new Map<string,any>();
        args.set("nativeMemoryType",nativeMemoryType);
        args.set("chartType",chartType);
        args.set("totalNS",TraceRow.range?.totalNS!);
        args.set("actionType","memory-chart");
        let arr:Array<HeapStruct> = await new Promise<any>((resolve, reject) => {
            procedurePool.submitWithName("logic1","native-memory-action",args,undefined,(res:any)=>{
                resolve(res)
            })
        })
        return arr;
    }

    initNativeMemory = async () => {
        let time = new Date().getTime();
        await new Promise<any>((resolve, reject) => {
            procedurePool.submitWithName("logic1","native-memory-init",{},undefined,(res:any)=>{
                resolve(res)
            })
        })
        let durTime = new Date().getTime() - time;
        info('The time to init the native memory data is: ', durTime)
    }

}