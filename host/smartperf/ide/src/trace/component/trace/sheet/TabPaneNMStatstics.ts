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

import {BaseElement, element} from "../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../base-ui/table/lit-table.js";
import {SelectionParam} from "../../../bean/BoxSelection.js";
import {
    queryNativeHookStatistics,
    queryNativeHookStatisticsMalloc,
    queryNativeHookStatisticsSubType
} from "../../../database/SqlLite.js";
import {NativeHookMalloc, NativeHookStatistics, NativeHookStatisticsTableData} from "../../../bean/NativeHook.js";
import {Utils} from "../base/Utils.js";
import {SpSystemTrace} from "../../SpSystemTrace.js";
import "./TabProgressBar.js"

@element('tabpane-native-statistics')
export class TabPaneNMStatstics extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<NativeHookStatisticsTableData> = []
    private native_type: Array<string> = ["All Heap & Anonymous VM", "All Heap", "All Anonymous VM"];
    private allMax: number = 0;
    private sortColumn: string = '';
    private sortType: number = 0;
    private currentSelection: SelectionParam | undefined

    set data(val: SelectionParam | any) {
        if(val == this.currentSelection){
            return;
        }
        this.currentSelection = val;
        this.allMax = 0;
        SpSystemTrace.EVENT_HEAP.map((heap) => {
            this.allMax += heap.sumHeapSize;
        });
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20) + "px"
        // @ts-ignore
        this.tbl?.recycleDataSource = [];
        Promise.all([queryNativeHookStatistics(val.leftNs, val.rightNs),
            queryNativeHookStatisticsSubType(val.leftNs, val.rightNs),
            queryNativeHookStatisticsMalloc(val.leftNs, val.rightNs)
        ]).then((values) => {
            let arr: Array<NativeHookStatisticsTableData> = [];
            let index1 = val.nativeMemory.indexOf(this.native_type[0])
            let index2 = val.nativeMemory.indexOf(this.native_type[1])
            let index3 = val.nativeMemory.indexOf(this.native_type[2])
            this.setMemoryTypeData(val, values[0], arr);
            if (index1 != -1 || index3 != -1) {
                this.setSubTypeTableData(values[1], arr);
            }
            let type = 0;
            if(index1 != -1 || (index2 != -1 && index3 != -1)){
                type = 0;
            }else{
                type = index2 != -1 ? 1 : 2;
            }
            this.setMallocTableData(values[2], arr,type);
            this.source = arr;
            this.sortByColumn(this.sortColumn,this.sortType)
        })
    }

    setMallocTableData(result: Array<NativeHookMalloc>, arr: Array<NativeHookStatisticsTableData>,type:number) {
        result.map((malloc) => {
            let data = new NativeHookStatisticsTableData();
            if(malloc.eventType == "AllocEvent"){
                data.memoryTap = "Malloc " + Utils.getByteWithUnit(malloc.heapSize);
            }else{
                data.memoryTap = "Mmap " + Utils.getByteWithUnit(malloc.heapSize);
            }
            data.existing = malloc.allocByte - malloc.freeByte
            data.allocCount = malloc.allocCount - malloc.freeCount;
            data.freeCount = malloc.freeCount;
            data.freeByte = malloc.freeByte;
            data.totalBytes = malloc.allocByte;
            data.totalCount = malloc.allocCount;
            data.max = malloc.heapSize;
            data.existingString = Utils.getByteWithUnit(data.existing);
            data.freeByteString = Utils.getByteWithUnit(malloc.freeByte);
            data.totalBytesString = Utils.getByteWithUnit(data.totalBytes);
            data.maxStr = Utils.getByteWithUnit(malloc.heapSize);
            data.existingValue = [data.existing, data.totalBytes, this.allMax];
            if(type == 0){
                arr.push(data);
            } else if(type == 1 && malloc.eventType == "AllocEvent"){
                arr.push(data)
            }else if(type ==2 && malloc.eventType == "MmapEvent"){
                arr.push(data)
            }else{}
        })
    }

    setSubTypeTableData(result: Array<NativeHookMalloc>, arr: Array<NativeHookStatisticsTableData>) {
        result.map((sub) => {
            let subType = SpSystemTrace.DATA_DICT.get(sub.subTypeId);
            if (subType != null && subType != undefined) {
                let data = new NativeHookStatisticsTableData();
                data.memoryTap = subType;
                data.existing = sub.allocByte - sub.freeByte
                data.allocCount = sub.allocCount - sub.freeCount;
                data.freeCount = sub.freeCount;
                data.freeByte = sub.freeByte;
                data.totalBytes = sub.allocByte;
                data.totalCount = sub.allocCount;
                data.max = sub.max;
                data.freeByteString = Utils.getByteWithUnit(sub.freeByte);
                data.existingString = Utils.getByteWithUnit(data.existing);
                data.totalBytesString = Utils.getByteWithUnit(data.totalBytes);
                data.maxStr = Utils.getByteWithUnit(sub.max);
                data.existingValue = [data.existing, data.totalBytes, this.allMax];
                arr.push(data);
            }
        })
    }

    setMemoryTypeData(val: SelectionParam, result: Array<NativeHookMalloc>, arr: Array<NativeHookStatisticsTableData>) {
        let all: NativeHookStatisticsTableData | null = null
        let heap: NativeHookStatisticsTableData | null = null
        let anonymous: NativeHookStatisticsTableData | null = null
        if (val.nativeMemory.indexOf(this.native_type[0]) != -1) {
            all = new NativeHookStatisticsTableData();
            all.memoryTap = this.native_type[0];
        }
        if (val.nativeMemory.indexOf(this.native_type[1]) != -1) {
            heap = new NativeHookStatisticsTableData();
            heap.memoryTap = this.native_type[1];
        }
        if (val.nativeMemory.indexOf(this.native_type[2]) != -1) {
            anonymous = new NativeHookStatisticsTableData();
            anonymous.memoryTap = this.native_type[2];
        }
        for (let hook of result) {
            if (all != null) {
                all.totalBytes += hook.allocByte;
                all.totalCount += hook.allocCount;
                all.freeByte += hook.freeByte;
                all.freeCount += hook.freeCount;
                if (hook.max > all.max) {
                    all.max = hook.max;
                    all.maxStr = Utils.getByteWithUnit(all.max);
                }
            }
            if (heap != null && hook.eventType == "AllocEvent") {
                heap.totalBytes += hook.allocByte;
                heap.totalCount += hook.allocCount;
                heap.freeByte += hook.freeByte;
                heap.freeCount += hook.freeCount;
                if (hook.max > heap.max) {
                    heap.max = hook.max;
                    heap.maxStr = Utils.getByteWithUnit(heap.max);
                }
            }
            if (anonymous != null && hook.eventType == "MmapEvent") {
                anonymous.totalBytes += hook.allocByte;
                anonymous.totalCount += hook.allocCount;
                anonymous.freeByte += hook.freeByte;
                anonymous.freeCount += hook.freeCount;
                if (hook.max > anonymous.max) {
                    anonymous.max = hook.max;
                    anonymous.maxStr = Utils.getByteWithUnit(anonymous.max);
                }
            }
        }
        if (all != null) {
            all.existing = all.totalBytes - all.freeByte;
            all.allocCount = all.totalCount - all.freeCount;
            all.existingString = Utils.getByteWithUnit(all.existing)
            all.totalBytesString = Utils.getByteWithUnit(all.totalBytes)
            all.freeByteString = Utils.getByteWithUnit(all.freeByte);
            all.existingValue = [all.existing, all.totalBytes, this.allMax]
            arr.push(all)
        }
        if (heap != null) {
            heap.existing = heap.totalBytes - heap.freeByte;
            heap.allocCount = heap.totalCount - heap.freeCount;
            heap.existingString = Utils.getByteWithUnit(heap.existing)
            heap.totalBytesString = Utils.getByteWithUnit(heap.totalBytes)
            heap.freeByteString = Utils.getByteWithUnit(heap.freeByte);
            heap.existingValue = [heap.existing, heap.totalBytes, this.allMax]
            arr.push(heap)
        }
        if (anonymous != null) {
            anonymous.existing = anonymous.totalBytes - anonymous.freeByte;
            anonymous.allocCount = anonymous.totalCount - anonymous.freeCount;
            anonymous.existingString = Utils.getByteWithUnit(anonymous.existing)
            anonymous.totalBytesString = Utils.getByteWithUnit(anonymous.totalBytes)
            anonymous.freeByteString = Utils.getByteWithUnit(anonymous.totalBytes - anonymous.existing)
            anonymous.existingValue = [anonymous.existing, anonymous.totalBytes, this.allMax]
            arr.push(anonymous)
        }
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-native-statstics');
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail.key, evt.detail.sort)
        });
    }

    sortByColumn(column: string, sort: number) {
        this.sortColumn = column;
        this.sortType = sort;
        if (sort == 0) {
            this.tbl!.recycleDataSource = this.source
        } else {
            let arr = [...this.source]
            if (column == "existingString") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? a.existing - b.existing : b.existing - a.existing
                })
            } else if (column == "allocCount") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? a.allocCount - b.allocCount : b.allocCount - a.allocCount
                })
            } else if (column == "freeByteString") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? (a.totalBytes - a.existing) - (b.totalBytes - b.existing) : (b.totalBytes -b.existing) - (a.totalBytes - a.existing)
                })
            } else if (column == "freeCount") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? a.freeCount - b.freeCount : b.freeCount - a.freeCount
                })
            } else if (column == "totalBytesString") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? a.totalBytes - b.totalBytes : b.totalBytes - a.totalBytes
                })
            } else if (column == "maxStr") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? a.max - b.max : b.max - a.max
                })
            } else if (column == "totalCount") {
                this.tbl!.recycleDataSource = arr.sort((a, b) => {
                    return sort == 1 ? a.totalCount - b.totalCount : b.totalCount - a.totalCount
                })
            }
        }
    }

    initHtml(): string {
        return `
<style>
:host{
    display: flex;
    flex-direction: column;
    padding: 10px 10px;
}
</style>
<lit-table id="tb-native-statstics" style="height: auto">
    <lit-table-column width="25%" title="Memory Type" data-index="memoryTap" key="memoryTap"  align="flex-start"></lit-table-column>
    <lit-table-column width="1fr" title="Existing" data-index="existingString" key="existingString"  align="flex-start" order></lit-table-column>
    <lit-table-column width="1fr" title="# Existing" data-index="allocCount" key="allocCount"  align="flex-start" order></lit-table-column>
    <lit-table-column width="1fr" title="Transient" data-index="freeByteString" key="freeByteString"  align="flex-start" order></lit-table-column>
    <lit-table-column width="1fr" title="# Transient" data-index="freeCount" key="freeCount"  align="flex-start" order></lit-table-column>
    <lit-table-column width="1fr" title="Total Bytes" data-index="totalBytesString" key="totalBytesString"  align="flex-start" order></lit-table-column>
    <lit-table-column width="1fr" title="# Total" data-index="totalCount" key="totalCount"  align="flex-start" order></lit-table-column>
    <lit-table-column width="1fr" title="Peak Value" data-index="maxStr" key="maxStr"  align="flex-start" order></lit-table-column>
    <lit-table-column width="160px" title="Existing / Total" data-index="existingValue" key="existingValue"  align="flex-start" >
        <template><tab-progress-bar data="{{existingValue}}"></tab-progress-bar></template>
    </lit-table-column>
</lit-table>
        `;
    }
}
