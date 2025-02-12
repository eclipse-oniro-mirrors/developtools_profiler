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
import {getTabPaneCounterSampleData,} from "../../../../database/SqlLite.js";
import {LitProgressBar} from "../../../../../base-ui/progress-bar/LitProgressBar.js";
import {Utils} from "../../base/Utils.js";

@element('tabpane-counter-sample')
export class TabPaneCounterSample extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private loadDataInCache: boolean = true;
    private selectionParam:SelectionParam | null | undefined;
    private progressEL:LitProgressBar | null | undefined;
    private loadingPage:any;
    private loadingList:number[] = [];
    private source:any[] = []
    private sortKey: string = "counter";
    private sortType: number = 0;

    set data(val: SelectionParam | any) {
        if(val == this.selectionParam){
            return;
        }
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible"
        this.selectionParam = val;
        // @ts-ignore
        this.tbl!.shadowRoot!.querySelector(".table").style.height = (this.parentElement!.clientHeight - 25) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.progressEL = this.shadowRoot!.querySelector<LitProgressBar>('.progress')
        this.loadingPage = this.shadowRoot!.querySelector('.loading');
        this.tbl = this.shadowRoot!.querySelector<LitTable>('#tb-states');
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
            if (this.parentElement!.clientHeight != 0) {
                // @ts-ignore
                this.tbl!.shadowRoot!.querySelector(".table").style.height = (this.parentElement!.clientHeight - 25) + "px"
                this.tbl!.reMeauseHeight()
                this.loadingPage.style.height = (this.parentElement!.clientHeight - 24) + "px"
            }
        }).observe(this.parentElement!);
    }

    queryDataByDB(val: SelectionParam | any) {
        this.loadingList.push(1)
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible";

        getTabPaneCounterSampleData(val.leftNs + val.recordStartNs, val.rightNs + val.recordStartNs, val.cpuStateFilterIds).then((result) => {
            this.loadingList.splice(0,1)
            if(this.loadingList.length == 0) {
                this.progressEL!.loading = false
                this.loadingPage.style.visibility = "hidden"
            }
            let sampleMap = new Map<any,any>()
            val.cpuStateFilterIds.forEach((a:number)=>{
                this.getInitTime(result.filter((f) => f.filterId == a),sampleMap,val)
            })
            let dataList:Array<any> = [];
            sampleMap.forEach(a=>{a.timeStr = Utils.getProbablyTime(a.time);dataList.push(a);});
            this.source = dataList;
            this.sortTable(this.sortKey,this.sortType)
        })
    }

    getInitTime(result:Array<any>,sampleMap:Map<any,any>,val:SelectionParam){
        let leftNs = val.leftNs + val.recordStartNs;
        let rightNs = val.rightNs + val.recordStartNs;
        if (result.length == 0) return;
        let idx = result.findIndex((a)=> a.ts >= (leftNs));
        if (idx !== 0) {
            result = result.slice(idx==-1?result.length-1:idx - 1, result.length);
        }
        if (result[0].ts < leftNs && idx !== 0) result[0].ts = leftNs;
        result.forEach((item,idx)=>{
            if ((idx + 1) == result.length) {
                item.time = (rightNs) - item.ts;
            }else {
                item.time = result[idx+1].ts - item.ts;
            }
            if (sampleMap.has(item.filterId+"-"+item.value)) {
                let obj = sampleMap.get(item.filterId+"-"+item.value);
                obj.time += item.time;
            }else {
                sampleMap.set(item.filterId+"-"+item.value,{
                    ...item,
                    counter:"Cpu "+item.cpu,
                })
            }
        });
    }

    sortTable(key: string,type:number){
        if(type == 0){
            this.tbl!.recycleDataSource = this.source
        }else{
            let arr = Array.from(this.source)
            arr.sort((a,b):number=>{
                if(key == "timeStr"){
                    if(type == 1){
                        return a.time - b.time ;
                    }else{
                        return b.time - a.time ;
                    }
                }else if(key == "counter"){
                    if (a.counter > b.counter) {
                        return type === 2 ? -1 : 1;
                    } else if (a.counter == b.counter)  {
                        return 0;
                    } else {
                        return type === 2 ? 1 : -1;
                    }
                }else if(key == "value"){
                    if(type == 1){
                        return a.value - b.value ;
                    }else{
                        return b.value - a.value ;
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
            padding: 10px 10px;
        }
        .progress{
            bottom: 5px;
            position: absolute;
            height: 1px;
            left: 0;
            right: 0;
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
        </style>
        <lit-table id="tb-states" style="height: auto" >
            <lit-table-column width="20%" title="Cpu" data-index="counter" key="counter" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Time" data-index="timeStr" key="timeStr" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Value" data-index="value" key="value" align="flex-start" order>
            </lit-table-column>
        </lit-table>
        <lit-progress-bar class="progress"></lit-progress-bar>
        <div class="loading"></div>
        `;
    }
}
