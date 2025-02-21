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

import "../../../../base-ui/table/lit-table-column.js";
import {BaseElement, element} from "../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../base-ui/table/lit-table.js";
import {SelectionParam} from "../../../bean/BoxSelection.js";
import {queryHeapAllData} from "../../../database/SqlLite.js";
import {Utils} from "../base/Utils.js";
import {HeapBean} from "../../../bean/HeapBean.js";
import {HeapTreeDataBean} from "../../../bean/HeapTreeDataBean.js";
import {SpSystemTrace} from "../../SpSystemTrace.js";
import {log} from "../../../../log/Log.js";

@element('tabpane-heap')
export class TabPaneHeap extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private HEAP_FRAME_DATA : Array<HeapTreeDataBean> = [];
    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20) + "px"
        queryHeapAllData(val.leftNs, val.rightNs, val.heapIds).then((allHeap) => {
            log("queryHeapAllData result size : " + allHeap.length)
            if (allHeap.length > 0) {
                let groups: any = {};
                let treeGroup: any = {}
                let treeData: HeapBean[] = []
                allHeap.forEach((heapData) => {
                    groups[heapData.eventId] = heapData
                })
                this.HEAP_FRAME_DATA.map((frame) => {
                    if (groups[frame.eventId]) {
                        treeGroup[frame.eventId] = treeGroup[frame.eventId] || []
                        frame.heapSize = groups[frame.eventId].heapSize
                        frame.startTs = groups[frame.eventId].startTs
                        frame.endTs = groups[frame.eventId].endTs
                        frame.eventType = groups[frame.eventId].eventType
                        treeGroup[frame.eventId].push(frame)
                    }
                })
                Object.keys(treeGroup).forEach((key) => {
                    if (treeGroup[key].length > 0) {
                        if (treeData.length > 0) {
                            this.merageTree(0, treeData, treeGroup[key], val)
                        } else {
                            let currentData = new HeapBean()
                            let firstData = treeGroup[key][0]
                            currentData.AllocationFunction = firstData.AllocationFunction
                            currentData.depth = firstData.depth
                            currentData.MoudleName = firstData.MoudleName
                            treeData.push(currentData)
                            this.merageTree(0, treeData, treeGroup[key], val)
                        }
                    }
                })
                this.setTreeDataSize(treeData)
                this.tbl!.recycleDataSource = treeData
            } else {
                this.tbl!.recycleDataSource = []
            }

        })
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-heap');
        this.range = this.shadowRoot?.querySelector('#time-range')
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
    }

    setTreeDataSize(list: HeapBean[]) {
        list.forEach((item) => {
            item.AllocationSize = Utils.getByteWithUnit(Number(item.AllocationSize))
            item.DeAllocationSize = Utils.getByteWithUnit(Number(item.DeAllocationSize))
            item.RemainingSize = Utils.getByteWithUnit(Number(item.RemainingSize))
            if (item.children.length > 0) {
                this.setTreeDataSize(item.children)
            }
        })
    }

    merageTree(depth: number, beanList: HeapBean[], list: HeapTreeDataBean[], selection: SelectionParam | any) {
        if (beanList.length > 0) {
            if (depth < list.length) {
                let treeData = list[depth]
                let currentData = beanList.find((item) => {
                    return treeData.MoudleName == item.MoudleName && treeData.AllocationFunction == item.AllocationFunction
                })
                if (currentData != undefined) {
                    (currentData.Allocations as number) += selection.leftNs < treeData.startTs ? 1 : 0;
                    (currentData.Deallocations as number) += selection.rightNs > treeData.endTs ? 1 : 0;
                    (currentData.AllocationSize as number) += selection.leftNs < treeData.startTs ? treeData.heapSize : 0;
                    (currentData.DeAllocationSize as number) += selection.rightNs > treeData.endTs ? treeData.heapSize : 0;
                    (currentData.Total as number) = (currentData.Allocations as number) - (currentData.Deallocations as number);
                    currentData.RemainingSize = (currentData.AllocationSize as number) - (currentData.DeAllocationSize as number)
                } else {
                    currentData = new HeapBean()
                    currentData.AllocationFunction = treeData.AllocationFunction
                    currentData.depth = treeData.depth
                    currentData.MoudleName = (treeData.MoudleName as string);
                    (currentData.Allocations as number) += selection.leftNs < treeData.startTs ? 1 : 0;
                    (currentData.Deallocations as number) += selection.rightNs > treeData.endTs ? 1 : 0;
                    (currentData.AllocationSize as number) += selection.leftNs < treeData.startTs ? treeData.heapSize : 0;
                    (currentData.DeAllocationSize as number) += selection.rightNs > treeData.endTs ? treeData.heapSize : 0;
                    currentData.Total = (currentData.Allocations as number) - (currentData.Deallocations as number);
                    currentData.RemainingSize = (currentData.AllocationSize as number) - (currentData.DeAllocationSize as number);
                    beanList.push(currentData)
                }
                if (depth + 1 < list.length && currentData.children.length == 0) {
                    let childrenBean = new HeapBean()
                    let nextData = list[depth + 1]
                    childrenBean.depth = depth + 1
                    childrenBean.MoudleName = nextData.MoudleName
                    childrenBean.AllocationFunction = nextData.AllocationFunction
                    currentData.children.push(childrenBean)
                }
                this.merageTree(depth + 1, currentData.children, list, selection)
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

        <lit-table id="tb-heap" style="height: auto" tree>
        <lit-table-column width="30%" title="Allocation Function" data-index="AllocationFunction" key="AllocationFunction" align="center" >
        </lit-table-column>
        <lit-table-column width="170px" title="Moudle Name" data-index="MoudleName" key="MoudleName" >
        </lit-table-column>
        <lit-table-column width="1fr" title="Allocations" data-index="Allocations" key="Allocations" align="center" >
        </lit-table-column>
        <lit-table-column width="1fr" title="Deallocations" data-index="Deallocations" key="Deallocations" align="center" >
        </lit-table-column>
        <lit-table-column width="1fr" title="Allocation Size" data-index="AllocationSize" key="AllocationSize" align="center" >
        </lit-table-column>
        <lit-table-column width="1fr" title="DeAllocation Size" data-index="DeAllocationSize" key="DeAllocationSize" align="center" >
        </lit-table-column>
        <lit-table-column title="Total Count" data-index="Total" key="Total" align="center" >
        </lit-table-column>
        <lit-table-column width="1fr" title="Remaining Size" data-index="RemainingSize" key="RemainingSize" align="center" >
        </lit-table-column>
        </lit-table>
        `;
    }
}