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
import {query, queryAllHookData, queryNativeHookSnapshotTypes} from "../../../database/SqlLite.js";
import {
    NativeHookCallInfo,
    NativeHookSampleQueryInfo,
    NativeHookSamplerInfo,
    NativeMemory
} from "../../../bean/NativeHook.js";
import {Utils} from "../base/Utils.js";
import "./TabPaneFilter.js"
import {FilterData, TabPaneFilter} from "./TabPaneFilter.js";
import "../../../../base-ui/slicer/lit-slicer.js";

@element('tabpane-native-sample')
export class TabPaneNMSampleList extends BaseElement {
    static tblData: LitTable | null | undefined;
    static tbl: LitTable | null | undefined;
    static filter: any
    static filterSelect: string = "0"
    static source: Array<NativeHookSamplerInfo> = [];
    static types: Array<string> = []
    static native_type: Array<string> = ["All Heap & Anonymous VM", "All Heap", "All Anonymous VM"];
    static tableMarkData: Array<NativeMemory> = []
    static selectionParam: SelectionParam | undefined = undefined
    static sampleTypes: Array<NativeHookSampleQueryInfo> = []
    static sampleTypesList: any[] = []

    set data(val: SelectionParam | any) {
        TabPaneNMSampleList.serSelection(val)
        this.filterAllList()
    }

    static serSelection(val: SelectionParam) {
        if (this.selectionParam !== val) {
            this.clearData()
            this.selectionParam = val
            this.initTypes()
        }
        if (val.nativeMemory.indexOf(this.native_type[0]) != -1) {
            this.types.push("'AllocEvent'");
            this.types.push("'MmapEvent'");
        } else {
            if (val.nativeMemory.indexOf(this.native_type[1]) != -1) {
                this.types.push("'AllocEvent'");
            }
            if (val.nativeMemory.indexOf(this.native_type[2]) != -1) {
                this.types.push("'MmapEvent'");
            }
        }
    }

    static initTypes() {
        queryNativeHookSnapshotTypes().then((result) => {
            if (result.length > 0) {
                this.sampleTypes = result
            }
        })
    }


    static addSampleData(data: any) {
        if (TabPaneNMSampleList.tableMarkData.indexOf(data) != -1) {
            return
        }
        TabPaneNMSampleList.tableMarkData.push(data)
        let rootSample = new NativeHookSamplerInfo()
        rootSample.snapshot = "Snapshot" + this.numberToWord(this.source.length + 1)
        rootSample.startTs = data.startTs
        rootSample.timestamp = Utils.getTimeString(data.startTs)
        rootSample.eventId = data.eventId
        rootSample.threadId = data.threadId
        rootSample.threadName = data.threadName
        this.queryAllHookInfo(data, rootSample)
    }


    static merageSampleData(leftTime: number, startNs: number, rootSample: NativeHookSampleQueryInfo, merageSample: NativeHookSampleQueryInfo) {
        if (merageSample.endTs >= startNs) {
            rootSample.growth += merageSample.growth
        }
        if (merageSample.startTs > leftTime) {
            rootSample.existing++;
            let childSample = new NativeHookSamplerInfo()//新增最下层的叶子节点
            childSample.snapshot = "0x" + merageSample.addr
            childSample.eventId = merageSample.eventId;
            childSample.heapSize = merageSample.growth
            childSample.growth = Utils.getByteWithUnit(merageSample.growth)
            childSample.totalGrowth = childSample.growth
            childSample.startTs = merageSample.startTs
            childSample.timestamp = Utils.getTimeString(merageSample.startTs);
            childSample.threadId = merageSample.threadId;
            childSample.threadName = merageSample.threadName;
            (childSample as any).existing = ""
            rootSample.children.push(childSample)
        }
        rootSample.total += merageSample.growth
    }

    static queryAllHookInfo(data: any, rootSample: NativeHookSamplerInfo) {
        let copyTypes = this.sampleTypes.map((type) => {
            let copyType = new NativeHookSampleQueryInfo()
            copyType.eventType = type.eventType
            copyType.subType = type.subType
            return copyType
        })
        queryAllHookData(data.startTs).then((result) => {
            if (result.length > 0) {
                let nameGroup: any = {}
                copyTypes.forEach((item) => {
                    nameGroup[item.eventType] = nameGroup[item.eventType] || []
                    nameGroup[item.eventType].push(item)
                })
                let leftTime = TabPaneNMSampleList.tableMarkData.length == 1 ? 0 : TabPaneNMSampleList.tableMarkData[TabPaneNMSampleList.tableMarkData.length - 2].startTs
                result.forEach((item) => {
                    item.threadId = rootSample.threadId;
                    item.threadName = rootSample.threadName;
                    if (nameGroup[item.eventType] != undefined) {
                        if (item.subType == null) {
                            this.merageSampleData(leftTime, data.startTs, nameGroup[item.eventType][0], item)
                        } else {
                            let filter = nameGroup[item.eventType].filter((type: any) => {
                                return type.subType == item.subType
                            })
                            if (filter.length > 0) {
                                this.merageSampleData(leftTime, data.startTs, filter[0], item)
                            }
                        }
                    }
                })
                if (this.sampleTypesList.length > 0) {
                    let sampleTypesListElement = this.sampleTypesList[this.sampleTypesList.length - 1];
                    sampleTypesListElement.forEach((item: any, index: number) => {
                        copyTypes[index].current = copyTypes[index].growth
                        if (index < copyTypes.length) {
                            copyTypes[index].growth -= item.current
                            copyTypes[index].total -= item.total
                        }
                    })
                } else {
                    copyTypes.forEach((item: any, index: number) => {
                        item.current = item.growth
                    })
                }
                this.sampleTypesList.push(copyTypes)
                this.createTree(nameGroup, rootSample)
                rootSample.tempList = [...rootSample.children]
                this.source.push(rootSample)
            }
        })
    }

    static createTree(nameGroup: any, rootSample: NativeHookSamplerInfo) {
        Object.keys(nameGroup).forEach((key) => {
            let parentSample = new NativeHookSamplerInfo()
            parentSample.snapshot = key
            if (nameGroup[key].length > 0) {
                nameGroup[key].forEach((child: any) => {
                    let childSample = new NativeHookSamplerInfo()
                    childSample.snapshot = child.subType || child.eventType
                    childSample.heapSize = child.growth
                    childSample.growth = Utils.getByteWithUnit(child.growth)
                    childSample.total = child.total
                    childSample.totalGrowth = Utils.getByteWithUnit(child.total)
                    childSample.existing = child.existing
                    childSample.currentSize = child.current
                    childSample.current = Utils.getByteWithUnit(child.current)
                    childSample.threadName = rootSample.threadName
                    childSample.threadId = rootSample.threadId
                    parentSample.merageObj(childSample)
                    if (childSample.snapshot != parentSample.snapshot) {//根据名称是否一致来判断是否需要添加子节点
                        childSample.children.push(...child.children)
                        parentSample.children.push(childSample)
                    } else {
                        parentSample.children.push(...child.children)
                    }
                })
            }
            rootSample.merageObj(parentSample)
            rootSample.children.push(parentSample)
        })
    }

    static prepChild(currentSample: NativeHookSamplerInfo, rootSample: NativeHookSamplerInfo) {
        currentSample.heapSize -= rootSample.heapSize
        currentSample.growth = Utils.getByteWithUnit(currentSample.heapSize)
        let currentMap: any = {}
        currentSample.children.forEach((currentChild) => {
            currentMap[currentChild.snapshot] = currentChild
        })
        rootSample.children.forEach((rootChild) => {
            if (currentMap[rootChild.snapshot] == undefined) {
                let perpSample = new NativeHookSamplerInfo()
                perpSample.snapshot = rootChild.snapshot
                currentMap[rootChild.snapshot] = perpSample
                currentSample.children.push(perpSample)
            }
            this.prepChild(currentMap[rootChild.snapshot], rootChild)
        })
    }

    static clearData() {
        this.types = []
        this.source = []
        this.tblData!.dataSource = []
        this.tbl!.recycleDataSource = []
        this.sampleTypesList = []
        this.tableMarkData = []
        TabPaneNMSampleList.filter!.firstSelect = "0"
    }

    static numberToWord(num: number) {
        let word = ""
        while (num > 0) {
            let end = num % 26
            end = end === 0 ? (end = 26) : end;
            word = String.fromCharCode(96 + end) + word
            num = (num - end) / 26
        }
        return word.toUpperCase()
    }

    startWorker(args: Map<string,any>, handler: Function) {
        query("NativeMemory", "", args, "native-memory-action").then((results) => {
            handler(results)
        })
    }

    setRightTableData(sample: NativeHookSamplerInfo) {
        let args = new Map<string,any>();
        args.set("eventId",sample.eventId);
        args.set("actionType","memory-stack");
        this.startWorker(args,(results: any[]) => {
            let source = [];
            if(results.length > 0){
                let thread = new NativeHookCallInfo();
                thread.threadId = sample.threadId;
                thread.threadName = sample.threadName;
                thread.title = `${sample.threadName ?? ""}【${sample.threadId}】`;
                thread.type = -1
                source.push(thread)
                source.push(...results)
            }
            // @ts-ignore
            TabPaneNMSampleList.tblData?.recycleDataSource = source;
        })
    }

    initElements(): void {
        TabPaneNMSampleList.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-native-sample');
        TabPaneNMSampleList.tbl!.addEventListener('row-click', (evt: any) => {
            // @ts-ignore
            this.setRightTableData(evt.detail.data);
        })
        TabPaneNMSampleList.tblData = this.shadowRoot?.querySelector<LitTable>('#tb-native-data');
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                TabPaneNMSampleList.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 10 - 31) + "px"
                TabPaneNMSampleList.tbl?.reMeauseHeight()
                // @ts-ignore
                TabPaneNMSampleList.tblData?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 10) + "px"
                TabPaneNMSampleList.tblData?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
        TabPaneNMSampleList.filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        this.shadowRoot?.querySelector<TabPaneFilter>("#filter")!.setSelectList(TabPaneNMSampleList.native_type, null)
        this.shadowRoot?.querySelector<TabPaneFilter>("#filter")!.getFilterData((data: FilterData) => {
            if (data.firstSelect) {
                TabPaneNMSampleList.filterSelect = data.firstSelect
                this.filterAllList()
            }
        })
        TabPaneNMSampleList.filter!.firstSelect = TabPaneNMSampleList.filterSelect

    }

    filterAllList() {
        TabPaneNMSampleList.source.forEach((rootSample) => {
            rootSample.heapSize = 0
            rootSample.existing = 0
            rootSample.total = 0
            if (TabPaneNMSampleList.filterSelect == "0") {
                rootSample.children = [...rootSample.tempList]
                rootSample.tempList.forEach((parentSample) => {
                    rootSample.heapSize += parentSample.heapSize
                    rootSample.existing += parentSample.existing
                    rootSample.total += parentSample.total
                })
                rootSample.growth = Utils.getByteWithUnit(rootSample.heapSize)
                rootSample.totalGrowth = Utils.getByteWithUnit(rootSample.total)
            } else if (TabPaneNMSampleList.filterSelect == "2") {
                if (rootSample.tempList.length > 1) {
                    rootSample.children = [rootSample.tempList[1]]
                    rootSample.heapSize += rootSample.tempList[1].heapSize
                    rootSample.existing += rootSample.tempList[1].existing
                    rootSample.growth = Utils.getByteWithUnit(rootSample.heapSize)
                    rootSample.total += rootSample.tempList[1].total
                    rootSample.totalGrowth = Utils.getByteWithUnit(rootSample.total)
                } else {
                    rootSample.children = []
                    rootSample.growth = ""
                    rootSample.totalGrowth = ""
                }
            } else {
                if (rootSample.tempList.length > 0) {
                    rootSample.children = [rootSample.tempList[0]]
                    rootSample.heapSize += rootSample.tempList[0].heapSize
                    rootSample.existing += rootSample.tempList[0].existing
                    rootSample.growth = Utils.getByteWithUnit(rootSample.heapSize)
                    rootSample.total += rootSample.tempList[0].total
                    rootSample.totalGrowth = Utils.getByteWithUnit(rootSample.total)
                } else {
                    rootSample.children = []
                    rootSample.growth = ""
                    rootSample.totalGrowth = ""
                }
            }
        })
        TabPaneNMSampleList.tbl!.recycleDataSource = TabPaneNMSampleList.source;
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
        }
        </style>
        <lit-slicer style="width:100%">
        <div style="width: 65%">
            <lit-table id="tb-native-sample" style="height: auto" tree>
                <lit-table-column width="25%" title="Snapshot" data-index="snapshot" key="snapshot"  align="flex-start" >
                </lit-table-column>
                <lit-table-column width="1fr" title="Timestamp" data-index="timestamp" key="timestamp"  align="flex-start"  >
                </lit-table-column>
                <lit-table-column width="1fr" title="Net Growth" data-index="growth" key="growth"  align="flex-start"  >
                </lit-table-column>
                <lit-table-column width="1fr" title="Total Growth" data-index="totalGrowth" key="totalGrowth"  align="flex-start"  >
                </lit-table-column>
                <lit-table-column width="1fr" title="# Existing" data-index="existing" key="existing"  align="flex-start"  >
                </lit-table-column>
            </lit-table>
            <tab-pane-filter id="filter" first></tab-pane-filter>
        </div>
        <lit-slicer-track ></lit-slicer-track>
        <lit-table id="tb-native-data" no-head style="height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)">
            <lit-table-column width="60px" title="" data-index="type" key="type"  align="flex-start" >
                <template>
                    <div v-if=" type == -1 ">Thread:</div>
                    <img src="img/library.png" size="20" v-if=" type == 1 ">
                    <img src="img/function.png" size="20" v-if=" type == 0 ">
                </template>
            </lit-table-column>
            <lit-table-column width="1fr" title="" data-index="title" key="title"  align="flex-start">
            </lit-table-column>
        </lit-table>
        </lit-slicer>
        `;
    }
}
