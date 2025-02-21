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
import {TraceRow} from "../trace/base/TraceRow.js";
import {procedurePool} from "../../database/Procedure.js";
import {
    getDiskIOLatencyChartDataByProcess,
    getDiskIOProcess,
    getFileSysChartDataByType, getFileSysVirtualMemoryChartData,
    hasFileSysData
} from "../../database/SqlLite.js";
import {FileSysChartStruct} from "../../database/ui-worker/ProcedureWorkerFileSystem.js";
import { ColorUtils } from "../trace/base/ColorUtils.js";

export class SpFileSystemChart {
    private trace: SpSystemTrace;
    static hoverFileSysStruct: FileSysChartStruct | undefined;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    async init() {
        let sys = await hasFileSysData();
        if(sys.length > 0){
            let fsCount = sys[0]['fsCount'] ?? 0;
            let vmCount = sys[0]['vmCount'] ?? 0;
            let ioCount = sys[0]['ioCount'] ?? 0;
            if(sys && sys.length > 0 && (fsCount > 0 || vmCount > 0 || ioCount > 0)){
                let folder = await this.initFolder();
                await this.initFileCallchain()
                if(fsCount > 0){
                    await this.initLogicalRead(folder);
                    await this.initLogicalWrite(folder);
                }
                if(vmCount > 0){
                    await this.initVirtualMemoryTrace(folder);
                }
            }
        }
    }

    async initFileCallchain(){
        return new Promise<any>((resolve, reject) => {
            procedurePool.submitWithName("logic0","fileSystem-init",SpSystemTrace.DATA_DICT,undefined,(res:any)=>{
                resolve(res)
            })
        })
    }

    async initFolder():Promise<TraceRow<any>>{
        let folder = new TraceRow();
        folder.rowId = `FileSystem`;
        folder.index = 0;
        folder.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM_GROUP
        folder.rowParentId = '';
        folder.folder = true;
        folder.name = `EBPF` ;/* & I/O Latency */
        folder.supplier = () => new Promise<Array<any>>((resolve) => resolve([]));
        folder.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        folder.selectChangeHandler = this.trace.selectChangeHandler;
        folder.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${folder.index}`, `${TraceRow.ROW_TYPE_FILE_SYSTEM_GROUP}`, folder.buildArgs({
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                useCache: useCache,
                scale: TraceRow.range?.scale || 50,
            }), !folder.isTransferCanvas ? folder.offscreen[0] : undefined, (res: any) => {
                folder.must = false;
            })
            folder.isTransferCanvas = true;
        }
        this.trace.rowsEL?.appendChild(folder)
        return folder;
    }

    async initLogicalRead(folder:TraceRow<any>){
        let row = new TraceRow();
        row.rowId = `FileSystemLogicalRead`;
        row.index = 1;
        row.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM
        row.rowParentId = folder.rowId;
        row.rowHidden = !folder.expansion
        row.rangeSelect = true;
        row.isHover = true;
        row.style.height = '40px'
        row.style.width = `100%`;
        row.setAttribute('children', '');
        row.name = `FileSystem Logical Read`;
        row.supplier = () => getFileSysChartDataByType(2);
        row.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        row.selectChangeHandler = this.trace.selectChangeHandler;
        row.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${(row.index) % procedurePool.processLen.length}`, `${TraceRow.ROW_TYPE_FILE_SYSTEM}-logical-read`, row.buildArgs({
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                useCache: useCache,
                chartColor:ColorUtils.MD_PALETTE[0],
                lineColor: row.getLineColor(),
                scale: TraceRow.range?.scale || 50,
            }), row.getTransferArray(), (res: any,hover: any) => {
                row.must = false;
                if (row.isHover) {
                    SpFileSystemChart.hoverFileSysStruct = hover;
                }
            })
            row.isTransferCanvas = true;
        }
        this.trace.rowsEL?.appendChild(row)
    }

    async initLogicalWrite(folder:TraceRow<any>){
        let row = new TraceRow();
        row.rowId = `FileSystemLogicalWrite`;
        row.index = 2;
        row.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM
        row.rowParentId = folder.rowId;
        row.rowHidden = !folder.expansion;
        row.rangeSelect = true;
        row.isHover = true;
        row.style.height = '40px'
        row.style.width = `100%`;
        row.setAttribute('children', '');
        row.name = `FileSystem Logical Write`;
        row.supplier = () => getFileSysChartDataByType(3);
        row.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        row.selectChangeHandler = this.trace.selectChangeHandler;
        row.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${(row.index) % procedurePool.processLen.length}`, `${TraceRow.ROW_TYPE_FILE_SYSTEM}-logical-write`, row.buildArgs({
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                useCache: useCache,
                lineColor: row.getLineColor(),
                chartColor:ColorUtils.MD_PALETTE[8],
                scale: TraceRow.range?.scale || 50,
            }),  row.getTransferArray(), (res: any,hover: any) => {
                row.must = false;
                if (row.isHover) {
                    SpFileSystemChart.hoverFileSysStruct = hover;
                }
            })
            row.isTransferCanvas = true;
        }
        this.trace.rowsEL?.appendChild(row)
    }

    async initDiskIOLatency(folder:TraceRow<any>){
        let row = new TraceRow();
        row.rowId = `FileSystemDiskIOLatency`;
        row.index = 4;
        row.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM
        row.rowParentId = folder.rowId;
        row.rowHidden = !folder.expansion
        row.style.height = '40px'
        row.style.width = `100%`;
        row.setAttribute('children', '');
        row.name = `Disk I/O Latency`;
        row.supplier = () => getDiskIOLatencyChartDataByProcess(true,0,[2,3]);
        row.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        row.selectChangeHandler = this.trace.selectChangeHandler;
        row.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${(row.index) % procedurePool.processLen.length}`, `${TraceRow.ROW_TYPE_FILE_SYSTEM}-disk-io`, row.buildArgs({
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                chartColor:ColorUtils.MD_PALETTE[0],
                useCache: useCache,
                scale: TraceRow.range?.scale || 50,
            }),  row.getTransferArray(), (res: any,hover: any) => {
                row.must = false;
                if (row.isHover) {
                    SpFileSystemChart.hoverFileSysStruct = hover;
                }
            })
            row.isTransferCanvas = true;
        }
        this.trace.rowsEL?.appendChild(row)
    }

    async initProcessDiskIOLatency(folder:TraceRow<any>){
        let processes = await getDiskIOProcess() || [];
        for (let i = 0,len = processes.length; i < len; i++) {
            let process = processes[i];
            let rowRead = new TraceRow();
            rowRead.index = 5 + 2 * i;
            rowRead.rowId = `FileSystemDiskIOLatency-read-${process['ipid']}`;
            rowRead.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM
            rowRead.rowParentId = folder.rowId;
            rowRead.rowHidden = !folder.expansion
            rowRead.style.height = '40px'
            rowRead.style.width = `100%`;
            rowRead.setAttribute('children', '');
            rowRead.name = `${process['name'] ?? 'Process'}(${process['pid']}) Max Read Latency`;
            rowRead.supplier = () => getDiskIOLatencyChartDataByProcess(false,process['ipid'],[2]);
            rowRead.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            rowRead.selectChangeHandler = this.trace.selectChangeHandler;
            rowRead.onThreadHandler = (useCache) => {
                procedurePool.submitWithName(`process${(rowRead.index) % procedurePool.processLen.length}`,
                    `${TraceRow.ROW_TYPE_FILE_SYSTEM}-disk-io-process-read-${process['pid']}`, rowRead.buildArgs({
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    chartColor:ColorUtils.MD_PALETTE[0],
                    useCache: useCache,
                    scale: TraceRow.range?.scale || 50,
                }),  rowRead.getTransferArray(), (res: any,hover: any) => {
                    rowRead.must = false;
                    if (rowRead.isHover) {
                        SpFileSystemChart.hoverFileSysStruct = hover;
                    }
                })
                rowRead.isTransferCanvas = true;
            }
            this.trace.rowsEL?.appendChild(rowRead)
            let rowWrite = new TraceRow();
            rowWrite.index = 5 + 2 * i + 1;
            rowWrite.rowId = `FileSystemDiskIOLatency-write-${process['ipid']}`;
            rowWrite.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM
            rowWrite.rowParentId = folder.rowId;
            rowWrite.rowHidden = !folder.expansion
            rowWrite.style.height = '40px'
            rowWrite.style.width = `100%`;
            rowWrite.setAttribute('children', '');
            rowWrite.name = `${process['name'] ?? 'Process'}(${process['pid']}) Max Write Latency`;
            rowWrite.supplier = () => getDiskIOLatencyChartDataByProcess(false,process['ipid'],[3]);
            rowWrite.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            rowWrite.selectChangeHandler = this.trace.selectChangeHandler;
            rowWrite.onThreadHandler = (useCache) => {
                procedurePool.submitWithName(`process${(rowWrite.index) % procedurePool.processLen.length}`,
                    `${TraceRow.ROW_TYPE_FILE_SYSTEM}-disk-io-process-write-${process['pid']}`, rowWrite.buildArgs({
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    chartColor:ColorUtils.MD_PALETTE[8],
                    useCache: useCache,
                    scale: TraceRow.range?.scale || 50,
                }),  rowWrite.getTransferArray(), (res: any,hover: any) => {
                    rowWrite.must = false;
                    if (rowWrite.isHover) {
                        SpFileSystemChart.hoverFileSysStruct = hover;
                    }
                })
                rowWrite.isTransferCanvas = true;
            }
            this.trace.rowsEL?.appendChild(rowWrite)
        }
    }

    async initVirtualMemoryTrace(folder:TraceRow<any>){
        let row = new TraceRow();
        row.rowId = `FileSystemVirtualMemory`;
        row.index = 3;
        row.rowType = TraceRow.ROW_TYPE_FILE_SYSTEM
        row.rowParentId = folder.rowId;
        row.rowHidden = !folder.expansion
        row.rangeSelect = true;
        row.style.height = '40px'
        row.style.width = `100%`;
        row.setAttribute('children', '');
        row.name = `Virtual Memory Trace`;
        row.supplier = () => getFileSysVirtualMemoryChartData();
        row.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        row.selectChangeHandler = this.trace.selectChangeHandler;
        row.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${(row.index) % procedurePool.processLen.length}`, `${TraceRow.ROW_TYPE_FILE_SYSTEM}-virtual-memory`, row.buildArgs({
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                chartColor:ColorUtils.MD_PALETTE[0],
                useCache: useCache,
                scale: TraceRow.range?.scale || 50,
            }),  row.getTransferArray(), (res: any,hover: any) => {
                row.must = false;
                if (row.isHover) {
                    SpFileSystemChart.hoverFileSysStruct = hover;
                }
            })
            row.isTransferCanvas = true;
        }
        this.trace.rowsEL?.appendChild(row)
    }
}