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
import {SelectionParam} from "../../../../bean/BoxSelection.js";
import "../../../../../base-ui/slicer/lit-slicer.js";
import {LitProgressBar} from "../../../../../base-ui/progress-bar/LitProgressBar.js";
import {procedurePool} from "../../../../database/Procedure.js";
import {
    FileSysEvent,
    VirtualMemoryEvent,
    VM_TYPE_MAP
} from "../../../../database/logic-worker/ProcedureLogicWorkerFileSystem.js";
import {FilterData, TabPaneFilter} from "../TabPaneFilter.js";
import {getTabVirtualMemoryType} from "../../../../database/SqlLite.js";

@element('tabpane-virtualmemory-event')
export class TabPaneVirtualMemoryEvents extends BaseElement {
    private defaultNativeTypes = ["All",...Object.values(VM_TYPE_MAP)];
    private native_type: Array<string> = [...this.defaultNativeTypes];
    private tbl: LitTable | null | undefined;
    private tblData: LitTable | null | undefined;
    private progressEL:LitProgressBar | null | undefined;
    private loadingList:number[] = []
    private loadingPage:any;
    private source: Array<VirtualMemoryEvent> = [];
    private queryDataSource: Array<VirtualMemoryEvent> = [];
    private sortKey: string = "startTs";
    private sortType: number = 0;
    private currentSelection: SelectionParam | undefined | null
    private statsticsSelection: Array<any> = []

    set data(val: SelectionParam | null | undefined) {
        if (val == this.currentSelection) {
            return
        }
        this.currentSelection = val
        this.initFilterTypes(val!).then(()=>{
            this.queryData(val!)
        });
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        // @ts-ignore
        this.tblData?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        this.tbl!.recycleDataSource = [];
        this.tblData!.recycleDataSource = [];


    }

    connectedCallback() {
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) - 10 - 33 + "px";
                this.tbl?.reMeauseHeight();
                // @ts-ignore
                this.tblData?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) - 10 -33 + "px"
                this.tblData?.reMeauseHeight()
                this.loadingPage.style.height = (this.parentElement!.clientHeight - 24) + "px"
            }
        }).observe(this.parentElement!)
    }

    initElements(): void {
        this.loadingPage = this.shadowRoot?.querySelector('.loading');
        this.progressEL = this.shadowRoot?.querySelector('.progress') as LitProgressBar;
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tbl');
        this.tblData = this.shadowRoot?.querySelector<LitTable>('#tbr');
        this.tbl!.addEventListener('row-click', (e) => {
            // @ts-ignore
            let data = e.detail.data;
            (data as any).isSelected = true;
            // @ts-ignore
            if ((e.detail as any).callBack) {
                // @ts-ignore
                (e.detail as any).callBack(true)
            }
            procedurePool.submitWithName("logic0","fileSystem-queryStack",
                { callchainId : data.callchainId },undefined,(res:any)=>{
                    this.tblData!.recycleDataSource = res;
                })
        });
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortKey = evt.detail.key
            // @ts-ignore
            this.sortType = evt.detail.sort
            // @ts-ignore
            this.sortTable(evt.detail.key,evt.detail.sort)
        })
        this.shadowRoot?.querySelector<TabPaneFilter>("#filter")!.getFilterData((data: FilterData) => {
            let index = parseInt(data.firstSelect||"0");
            if(index > this.defaultNativeTypes.length -1){
                this.filterTypeData(this.statsticsSelection[index - this.defaultNativeTypes.length])
            }else {
                this.filterTypeData(undefined)
            }
            this.tbl!.recycleDataSource = this.source
        })
    }

    async initFilterTypes(val: SelectionParam){
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        let typeKeys = await getTabVirtualMemoryType(val.leftNs,val.rightNs);
        this.defaultNativeTypes = ["All"]
        this.statsticsSelection = []
        typeKeys.forEach((item)=>{
            // @ts-ignore
            this.defaultNativeTypes.push(VM_TYPE_MAP[item.type+""])
        })
        this.native_type = [...this.defaultNativeTypes]
        filter!.setSelectList([...this.defaultNativeTypes],null,"Operation Type")
        filter!.firstSelect = "0"
    }

    async fromStastics(val: SelectionParam | any) {
        if(val.fileSystemVMData == undefined){
            return
        }
        this.tblData!.recycleDataSource = []
        this.tblData?.clearAllSelection(undefined)
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        if (this.currentSelection != val) {
           await this.initFilterTypes(val)
        }
        let typeIndexOf = this.native_type.indexOf(val.fileSystemVMData.path.value);
        if(typeIndexOf == -1){
            this.statsticsSelection.push(val.fileSystemVMData.path)
            this.native_type.push(val.fileSystemVMData.path.value)
            typeIndexOf = this.native_type.length - 1
        }
        if (this.currentSelection != val) {
            this.currentSelection = val
            filter!.setSelectList(this.native_type, null,"Operation Type")
            filter!.firstSelect = typeIndexOf + ""
            this.queryData(val)
        }else {
            if(typeIndexOf == parseInt(filter!.firstSelect)){
                return
            }
            filter!.setSelectList(this.native_type, null,"Operation Type")
            filter!.firstSelect = typeIndexOf + ""
            this.filterTypeData(val?.fileSystemVMData?.path||undefined)
            val.fileSystemVMData = undefined
            this.tbl!.recycleDataSource = this.source
        }
    }

    queryData(val: SelectionParam){
        this.loadingList.push(1)
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible"
        this.source = [];
        this.queryDataSource = [];
        procedurePool.submitWithName("logic0","fileSystem-queryVMEvents",
            {leftNs:val.leftNs,rightNs:val.rightNs,typeArr:val.fileSystemType},undefined,(res:any)=>{
                this.source = this.source.concat(res.data)
                this.queryDataSource = this.queryDataSource.concat(res.data)
                this.filterTypeData(val?.fileSystemVMData?.path||undefined)
                val.fileSystemVMData = undefined
                res.data = null;
                if(!res.isSending){
                    this.tbl!.recycleDataSource = this.source;
                    this.loadingList.splice(0,1)
                    if(this.loadingList.length == 0) {
                        this.progressEL!.loading = false
                        this.loadingPage.style.visibility = "hidden"
                    }
                }
            })
    }

    filterTypeData(pathData:any){
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        let firstSelect = filter!.firstSelect;
        let type = -1;
        let tid = -1;
        let pid = -1;
        if(parseInt(firstSelect) <= this.defaultNativeTypes.length - 1){
            let typeEntry = Object.entries(VM_TYPE_MAP).find((entry)=>{
                return entry[1] == this.defaultNativeTypes[parseInt(firstSelect)]
            })
            type = typeEntry?parseInt(typeEntry[0]):0
        }else if(pathData!=undefined){
            type = parseInt(pathData.type);
            tid = pathData.tid||-1;
            pid = pathData.pid||-1;
        }else if(pathData==undefined){
            return
        }
        let isTidFilter = false;
        let isPidFilter = false;
        let isTypeFilter = false;
        this.source = this.queryDataSource.filter((item)=>{
            if(tid == -1){
                isTidFilter = true
            }else {
                isTidFilter = item.tid == tid
            }
            if(pid == -1){
                isPidFilter = true
            }else{
                isPidFilter = item.pid == pid
            }
            isTypeFilter = type == 0 || item.type == type;
            return isTidFilter&&isPidFilter&&isTypeFilter
        })
    }

    sortTable(key: string,type:number){
        if(type == 0){
            this.tbl!.recycleDataSource = this.source
        }else{
            let arr = Array.from(this.source)
            arr.sort((a,b):number=>{
                if(key == "startTsStr"){
                    if(type == 1){
                        return a.startTs - b.startTs ;
                    }else{
                        return b.startTs - a.startTs ;
                    }
                }else if(key == "durStr"){
                    if(type == 1){
                        return a.dur - b.dur ;
                    }else{
                        return b.dur - a.dur ;
                    }
                }else if(key == "thread"){
                    if (a.thread > b.thread) {
                        return type === 2 ? 1 : -1;
                    } else if (a.thread == b.thread)  {
                        return 0;
                    } else {
                        return type === 2 ? -1 : 1;
                    }
                }else if(key == "sizeStr"){
                    if(type == 1){
                        return a.size - b.size ;
                    }else{
                        return b.size - a.size ;
                    }
                }else{
                    return 0;
                }
            })
            this.tbl!.recycleDataSource = arr;
        }
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
            z-index: 99;
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
            <div style="display: flex;flex-direction: row;">
                <lit-slicer style="width:100%">
                    <div style="width: 65%">
                        <lit-table id="tbl" style="height: auto">
                            <lit-table-column width="1fr" title="Start Time" data-index="startTsStr" key="startTsStr" align="flex-start" order></lit-table-column>
                            <lit-table-column width="1fr" title="Duration" data-index="durStr" key="durStr" align="flex-start" order></lit-table-column>
                            <lit-table-column width="1fr" title="Thread" data-index="thread" key="thread" align="flex-start" order></lit-table-column>
                            <lit-table-column width="1fr" title="Operation" data-index="operation" key="operation" align="flex-start" ></lit-table-column>
                            <lit-table-column width="1fr" title="Adress" data-index="address" key="address" align="flex-start" ></lit-table-column>
                            <lit-table-column width="1fr" title="Size" data-index="sizeStr" key="sizeStr" align="flex-start" order></lit-table-column>
                        </lit-table>
                    </div>
                    <lit-slicer-track ></lit-slicer-track>
                    <lit-table id="tbr" no-head style="height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)">
                        <lit-table-column width="60px" title="" data-index="type" key="type"  align="flex-start" >
                            <template>
                                <div v-if=" type == -1 ">Thread:</div>
                                <img src="img/library.png" size="20" v-if=" type == 1 ">
                                <img src="img/function.png" size="20" v-if=" type == 0 ">
                            </template>
                        </lit-table-column>
                        <lit-table-column width="1fr" title="" data-index="symbol" key="symbol"  align="flex-start">
                        </lit-table-column>
                    </lit-table>
                </lit-slicer>
            </div>
            <lit-progress-bar class="progress"></lit-progress-bar>
            <tab-pane-filter id="filter" first></tab-pane-filter>
            <div class="loading"></div>
        </div>
`;
    }
}
