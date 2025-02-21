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

import {BaseElement, element} from "../../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../../base-ui/table/lit-table.js";
import "../../../../../base-ui/slicer/lit-slicer.js";
import {SelectionParam} from "../../../../bean/BoxSelection.js";
import {query, queryNativeHookEventTid} from "../../../../database/SqlLite.js";
import { NativeHookStatistics, NativeMemory,NativeHookCallInfo} from "../../../../bean/NativeHook.js";
import "../TabPaneFilter.js"
import {FilterData, TabPaneFilter} from "../TabPaneFilter.js";
import {TabPaneNMSampleList} from "./TabPaneNMSampleList.js";
import {LitProgressBar} from "../../../../../base-ui/progress-bar/LitProgressBar.js";
import {procedurePool} from "../../../../database/Procedure.js";

@element('tabpane-native-memory')
export class TabPaneNMemory extends BaseElement {
    private defaultNativeTypes = ["All Heap & Anonymous VM", "All Heap", "All Anonymous VM"];
    private tbl: LitTable | null | undefined;
    private tblData: LitTable | null | undefined;
    private progressEL:LitProgressBar | null | undefined;
    private loadingList:number[] = []
    private loadingPage:any;
    private source: Array<NativeMemory> = []
    private native_type: Array<string> = [...this.defaultNativeTypes];
    private statsticsSelection: Array<any> = []
    private queryResult: Array<NativeHookStatistics> = []
    private filterAllocationType: string = "0"
    private filterNativeType: string = "0"
    private currentSelection: SelectionParam | undefined
    private rowSelectData: any = undefined;
    private sortColumn: string = '';
    private sortType: number = 0;
    private leftNs:number = 0;
    private rightNs:number = 0;

    set data(val: SelectionParam | any) {
        if (val == this.currentSelection) {
            return
        }
        this.currentSelection = val
        this.initFilterTypes()
        this.queryData(val)
    }

    queryData(val: SelectionParam | any) {
        let types: Array<string> = []
        if (val.nativeMemory.indexOf(this.defaultNativeTypes[0]) != -1) {
            types.push("'AllocEvent'");
            types.push("'MmapEvent'");
        } else {
            if (val.nativeMemory.indexOf(this.defaultNativeTypes[1]) != -1) {
                types.push("'AllocEvent'");
            }
            if (val.nativeMemory.indexOf(this.defaultNativeTypes[2]) != -1) {
                types.push("'MmapEvent'");
            }
        }
        TabPaneNMSampleList.serSelection(val)
        // @ts-ignore
        this.tbl?.shadowRoot?.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        // @ts-ignore
        this.tblData?.shadowRoot?.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        // @ts-ignore
        this.tblData?.recycleDataSource = [];
        // @ts-ignore
        this.tbl?.recycleDataSource = [];
        this.leftNs = val.leftNs;
        this.rightNs = val.rightNs;
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible"
        queryNativeHookEventTid(val.leftNs, val.rightNs, types).then((result) => {
            this.queryResult = result
            this.getDataByNativeMemoryWorker(val);
        })
    }

    getDataByNativeMemoryWorker(val: SelectionParam | any){
        let args = new Map<string,any>();
        args.set("data",this.queryResult);
        args.set("filterAllocType",this.filterAllocationType);
        args.set("filterEventType",this.filterNativeType);
        args.set("leftNs",val.leftNs);
        args.set("rightNs",val.rightNs);
        let selections:Array<any> = [];
        if(this.statsticsSelection.length > 0){
            this.statsticsSelection.map((memory) => {
                selections.push({memoryTap:memory.memoryTap, max:memory.max})
            })
        }
        args.set("statisticsSelection",selections);
        args.set("actionType","native-memory");
        this.startWorker(args,(results: any[]) => {
            this.tblData!.recycleDataSource = []
            this.progressEL!.loading = false
            if (results.length > 0) {
                this.source = results;
                this.sortByColumn(this.sortColumn,this.sortType);
            }else {
                this.source = []
                this.tbl!.recycleDataSource = [];
            }
        })
    }

    startWorker(args: Map<string,any>, handler: Function) {
        this.loadingList.push(1)
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible"
        procedurePool.submitWithName("logic1","native-memory-action",args,undefined,(res:any)=>{
            handler(res);
            this.loadingList.splice(0,1)
            if(this.loadingList.length == 0) {
                this.progressEL!.loading = false
                this.loadingPage.style.visibility = "hidden"
            }
        })
    }

    fromStastics(val: SelectionParam | any) {
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        if (this.currentSelection != val) {
            this.initFilterTypes()
        }
        let typeIndexOf = this.native_type.indexOf(val.statisticsSelectData.memoryTap);
        if (this.statsticsSelection.indexOf(val.statisticsSelectData) == -1 && typeIndexOf == -1) {
            this.statsticsSelection.push(val.statisticsSelectData)
            this.native_type.push(val.statisticsSelectData.memoryTap)
            typeIndexOf = this.native_type.length - 1
        }else{
            let index = this.statsticsSelection.findIndex((mt) => mt.memoryTap == val.statisticsSelectData.memoryTap);
            if(index != -1){
                this.statsticsSelection[index] = val.statisticsSelectData;
            }
        }
        if (this.currentSelection != val) {
            this.currentSelection = val
            filter!.setSelectList(null, this.native_type)
            filter!.secondSelect = typeIndexOf + ""
            this.filterNativeType = typeIndexOf + ""
            this.queryData(val)
        } else {
            this.tblData!.recycleDataSource = [];
            this.rowSelectData = undefined
            filter!.setSelectList(null, this.native_type)
            filter!.secondSelect = typeIndexOf + ""
            this.filterNativeType = typeIndexOf + ""
            //直接将当前数据过滤即可
            this.getDataByNativeMemoryWorker(val)
        }
    }

    initFilterTypes() {
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        this.queryResult = []
        this.native_type = [...this.defaultNativeTypes]
        this.statsticsSelection = []
        filter!.setSelectList(null, [...this.defaultNativeTypes])
        filter!.firstSelect = "0"
        filter!.secondSelect = "0"
        this.filterAllocationType = "0"
        this.filterNativeType = "0"
        this.rowSelectData = undefined
    }

    initElements(): void {
        this.loadingPage = this.shadowRoot?.querySelector('.loading');
        this.progressEL = this.shadowRoot?.querySelector('.progress') as LitProgressBar
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-native-memory');
        this.tblData = this.shadowRoot?.querySelector<LitTable>('#tb-native-data');
        this.tbl!.addEventListener("row-click", (e) => {
            // @ts-ignore
            let data = (e.detail.data as NativeMemory);
            this.rowSelectData = data
            this.setRightTableData(data);
            document.dispatchEvent(new CustomEvent('triangle-flag', {detail: {time: data.startTs, type: "triangle"}}));
        })
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail.key,evt.detail.sort)
        });
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        this.shadowRoot?.querySelector<TabPaneFilter>("#filter")!.getFilterData((data: FilterData) => {
            if (data.mark) {
                document.dispatchEvent(new CustomEvent('triangle-flag', {
                    detail: {
                        time: "", type: "square", timeCallback: (t: any) => {
                            let minTs = 0
                            let minItem: any = undefined
                            let filterTemp = this.source.filter((tempItem) => {
                                if (minTs == 0 || (tempItem.startTs - t != 0 && Math.abs(tempItem.startTs - t) < minTs)) {
                                    minTs = Math.abs(tempItem.startTs - t)
                                    minItem = tempItem
                                }
                                return tempItem.startTs == t
                            })
                            if (filterTemp.length > 0) {
                                filterTemp[0].isSelected = true
                            } else {
                                if (minItem) {
                                    filterTemp.push(minItem)
                                    minItem.isSelected = true
                                }
                            }
                            if (filterTemp.length > 0) {
                                this.rowSelectData = filterTemp[0]
                                let currentSelection = this.queryResult.filter((item) => {
                                    return item.startTs == this.rowSelectData.startTs
                                })
                                if (currentSelection.length > 0) {
                                    currentSelection[0].isSelected = true
                                }
                                TabPaneNMSampleList.addSampleData(this.rowSelectData)
                                this.tbl!.scrollToData(this.rowSelectData)
                            }
                        }
                    }
                }));
            } else {
                this.filterAllocationType = data.firstSelect || "0"
                this.filterNativeType = data.secondSelect || "0"
                this.getDataByNativeMemoryWorker(this.currentSelection)
            }
        })
        filter!.firstSelect = "1"
    }

    connectedCallback() {
        super.connectedCallback();
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) - 10 - 31 + "px";
                this.tbl?.reMeauseHeight();
                // @ts-ignore
                this.tblData?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) - 10 -31 + "px"
                this.tblData?.reMeauseHeight()
                this.loadingPage.style.height = (this.parentElement!.clientHeight - 24) + "px"
            }
        }).observe(this.parentElement!);
    }

    sortByColumn(column:string,sort:number){
        this.sortColumn = column;
        this.sortType = sort;
        if(sort == 0){
            this.tbl!.recycleDataSource = this.source
        }else{
            let arr = [...this.source]
            if(column == "index"){
                this.tbl!.recycleDataSource = arr.sort((a,b)=>{
                    return sort == 1 ? a.index - b.index : b.index - a.index
                })
            }else if(column == "addr"){
                this.tbl!.recycleDataSource = arr.sort((a,b)=>{
                    if(sort == 1){
                        if(a.addr > b.addr){
                            return 1
                        }else if(a.addr == b.addr){
                            return 0;
                        }else{
                            return -1;
                        }
                    }else{
                        if(b.addr > a.addr){
                            return 1
                        }else if(a.addr == b.addr){
                            return 0;
                        }else{
                            return -1;
                        }
                    }
                })
            }else if(column == "timestamp"){
                this.tbl!.recycleDataSource = arr.sort((a,b)=>{
                    return sort == 1 ? a.startTs - b.startTs : b.startTs - a.startTs
                })
            }else if(column == "heapSizeUnit"){
                this.tbl!.recycleDataSource = arr.sort((a,b)=>{
                    return sort == 1 ? a.heapSize - b.heapSize : b.heapSize - a.heapSize
                })
            }else if(column == "library"){
                this.tbl!.recycleDataSource = arr.sort((a,b)=>{
                    if(sort == 1){
                        if(a.library > b.library){
                            return 1
                        }else if(a.library == b.library){
                            return 0;
                        }else{
                            return -1;
                        }
                    }else{
                        if(b.library > a.library){
                            return 1
                        }else if(a.library == b.library){
                            return 0;
                        }else{
                            return -1;
                        }
                    }
                })
            }else if(column == "symbol"){
                this.tbl!.recycleDataSource = arr.sort((a,b)=>{
                    if(sort == 1){
                        if(a.symbol > b.symbol){
                            return 1
                        }else if(a.symbol == b.symbol){
                            return 0;
                        }else{
                            return -1;
                        }
                    }else{
                        if(b.symbol > a.symbol){
                            return 1
                        }else if(a.symbol == b.symbol){
                            return 0;
                        }else{
                            return -1;
                        }
                    }
                })
            }
        }
    }

    setRightTableData(hook: NativeMemory) {
        let args = new Map<string,any>();
        args.set("eventId",hook.eventId);
        args.set("actionType","memory-stack");
        this.startWorker(args,(results: any[]) => {
            let thread = new NativeHookCallInfo();
            thread.threadId = hook.threadId;
            thread.threadName = hook.threadName;
            thread.title = `${hook.threadName ?? ""}【${hook.threadId}】`;
            thread.type = -1
            let source = [];
            source.push(thread);
            source.push(...results)
            this.progressEL!.loading = false
            this.tblData!.dataSource = source;
        })
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
        }
        .loading{
            bottom: 0;
            position: absolute;
            left: 0;
            right: 0;
            width:100%;
            background:transparent;
            z-index: 999999;
        }
        .progress{
            bottom: 33px;
            position: absolute;
            height: 1px;
            left: 0;
            right: 0;
        }
        tab-pane-filter {
            border: solid rgb(216,216,216) 1px;
            float: left;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        </style>
        <div style="display: flex;flex-direction: column">
            <div style="display: flex;flex-direction: row">
                <lit-slicer style="width:100%">
                    <div style="width: 65%">
                        <lit-table id="tb-native-memory" style="height: auto">
                            <lit-table-column width="60px" title="#" data-index="index" key="index"  align="flex-start" order>
                            </lit-table-column>
                            <lit-table-column width="1fr" title="Address" data-index="addr" key="addr"  align="flex-start" order>
                            </lit-table-column>
                            <lit-table-column width="1fr" title="Memory Type" data-index="eventType" key="eventType"  align="flex-start">
                            </lit-table-column>
                            <lit-table-column width="1fr" title="Timestamp" data-index="timestamp" key="timestamp"  align="flex-start" order>
                            </lit-table-column>
                            <lit-table-column width="1fr" title="State" data-index="state" key="state"  align="flex-start">
                            </lit-table-column>
                            <lit-table-column width="1fr" title="Size" data-index="heapSizeUnit" key="heapSizeUnit"  align="flex-start" order>
                            </lit-table-column>
                            <lit-table-column width="20%" title="Responsible Library" data-index="library" key="library"  align="flex-start" order>
                            </lit-table-column>
                            <lit-table-column width="20%" title="Responsible Caller" data-index="symbol" key="symbol"  align="flex-start" order>
                            </lit-table-column>
                        </lit-table>
                    </div>
                    <lit-slicer-track ></lit-slicer-track>
                    <lit-table id="tb-native-data" no-head style="height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)">
                        <lit-table-column width="80px" title="" data-index="type" key="type"  align="flex-start" >
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
            </div>
            <lit-progress-bar class="progress"></lit-progress-bar>
            <tab-pane-filter id="filter" mark first second></tab-pane-filter>
            <div class="loading"></div>
        </div>
        `;
    }
}
