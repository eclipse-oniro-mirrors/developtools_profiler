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
import {FileSysEvent} from "../../../../database/logic-worker/ProcedureLogicWorkerFileSystem.js";
import {procedurePool} from "../../../../database/Procedure.js";

@element('tabpane-filesystem-desc-time-slice')
export class TabPaneFileSystemDescTimeSlice extends BaseElement {
    private tbl: LitTable | null | undefined;
    private tblData: LitTable | null | undefined;
    private progressEL:LitProgressBar | null | undefined;
    private loadingList:number[] = []
    private loadingPage:any;
    private source: Array<FileSysEvent> = [];
    private sortKey: string = "startTs";
    private sortType: number = 0;
    private currentSelection: SelectionParam | undefined | null

    set data(val: SelectionParam | null | undefined) {
        if (val == this.currentSelection) {
            return
        }
        this.currentSelection = val
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        // @ts-ignore
        this.tblData?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        this.tbl!.recycleDataSource = [];
        this.tblData!.recycleDataSource = [];
        if (val) {
            this.loadingList.push(1)
            this.progressEL!.loading = true
            this.loadingPage.style.visibility = "visible"
            let startNs = (window as any).recordStartNS ?? 0;
            this.source = [];
            procedurePool.submitWithName("logic0","fileSystem-queryFileSysEvents",
                {leftNs:startNs + val.leftNs,rightNs: startNs + val.rightNs,typeArr:[0],tab:"time-slice"},undefined,(res:any)=>{
                    this.source = this.source.concat(res.data)
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
    }

    initElements(): void {
        this.loadingPage = this.shadowRoot?.querySelector('.loading');
        this.progressEL = this.shadowRoot?.querySelector('.progress') as LitProgressBar;
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tbl');
        this.tblData = this.shadowRoot?.querySelector<LitTable>('#tbr');
        this.tbl!.addEventListener('row-click', (e) => {
            // @ts-ignore
            let data = (e.detail.data as FileSysEvent);
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
                } else if(key == "durStr"){
                    if(type == 1){
                        return a.dur - b.dur ;
                    }else{
                        return b.dur - a.dur ;
                    }
                } else if(key == "process"){
                    if (a.process > b.process) {
                        return type === 2 ? 1 : -1;
                    } else if (a.process == b.process)  {
                        return 0;
                    } else {
                        return type === 2 ? -1 : 1;
                    }
                } else if(key == "fd"){
                    if(type == 1){
                        return a.fd - b.fd ;
                    }else{
                        return b.fd - a.fd ;
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
            <div style="display: flex;flex-direction: row">
                <lit-slicer style="width:100%">
                    <div style="width: 65%">
                        <lit-table id="tbl" style="height: auto">
                            <lit-table-column width="200px" title="Open Time" data-index="startTsStr" key="startTsStr" align="flex-start" order></lit-table-column>
                            <lit-table-column width="200px" title="Open Duration" data-index="durStr" key="surStr" align="flex-start" order></lit-table-column>
                            <lit-table-column width="200px" title="Process" data-index="process" key="process" align="flex-start" order></lit-table-column>
                            <lit-table-column width="160px" title="File Descriptor" data-index="fd" key="fd" align="flex-start" order></lit-table-column>
<!--                            <lit-table-column width="300px" title="Path" data-index="path" key="path" align="flex-start" ></lit-table-column>-->
                            <lit-table-column width="600px" title="Backtrace" data-index="backtrace" key="backtrace" align="flex-start" >
                                <template>
                                    <div>
                                        <span>{{backtrace[0]}}</span>
                                        <span v-if="backtrace.length > 1">⬅</span>
                                        <span v-if="backtrace.length > 1"style="color: #565656"> {{backtrace[1]}}</span>
                                    </div>
                                </template>
                            </lit-table-column>
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
            <tab-pane-filter id="filter"></tab-pane-filter>
            <div class="loading"></div>
        </div>
`;
    }
}
