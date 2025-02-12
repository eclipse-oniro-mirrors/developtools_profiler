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
import {
    getTabPaneVirtualMemoryStatisticsData,
} from "../../../../database/SqlLite.js";
import {Utils} from "../../base/Utils.js";
import {LitProgressBar} from "../../../../../base-ui/progress-bar/LitProgressBar.js";
import {TabPaneFilter} from "../TabPaneFilter.js";
import  "../TabPaneFilter.js";
import {VM_TYPE_MAP} from "../../../../database/logic-worker/ProcedureLogicWorkerFileSystem.js";

@element('tabpane-virtual-memory-statistics')
export class TabPaneVirtualMemoryStatistics extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private loadDataInCache: boolean = true;
    private selectionParam:SelectionParam | null | undefined;
    private progressEL:LitProgressBar | null | undefined;
    private filter: TabPaneFilter | null | undefined;
    private loadingPage:any;
    private loadingList:number[] = [];
    private source: Array<any> = [];
    private typeList: Array<string> = ["OPEN", "CLOSE", "READ" , "WRITE"];
    private sortKey: string = "";
    private sortType: number = 0;
    private resultData: Array<any> = [];

    set data(val: SelectionParam | any) {
        if(val == this.selectionParam){
            return;
        }
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible"
        this.selectionParam = val;
        // @ts-ignore
        this.tbl!.shadowRoot!.querySelector(".table").style.height = (this.parentElement!.clientHeight - 20) + "px"
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
            this.sortType = evt.detail.sort;

            let newSource = JSON.parse(JSON.stringify(this.source));
            if (this.sortType != 0 && newSource.length > 0) this.sortTable(newSource[0],this.sortKey);
            this.tbl!.recycleDataSource = newSource;
        })
        this.filter = this.shadowRoot!.querySelector<TabPaneFilter>("#filter");
        this.filter!.getStatisticsTypeData((type)=>{
            if (type=="operation") {
                this.sortStatus(this.resultData,"ipid","itid")
            }else {
                this.sortStatus(this.resultData,"type","ipid")
            }
            this.tbl!.shadowRoot!.querySelector("div > div.thead > div > div:nth-child(1) > label")!.textContent = type=="operation"?"Process/Thread/Operation":"Operation/Process/Thread"
        })

    }

    connectedCallback() {
        super.connectedCallback();
        new ResizeObserver((entries) => {
            if (this.parentElement!.clientHeight != 0) {
                // @ts-ignore
                this.tbl!.shadowRoot!.querySelector(".table").style.height = (this.parentElement!.clientHeight - 10 -31) + "px"
                this.tbl!.reMeauseHeight()
                this.loadingPage.style.height = (this.parentElement!.clientHeight - 24) + "px"
            }
        }).observe(this.parentElement!);
    }

    getInitData(item:any,nameTitle:any = "pname",subtitle:any = null){
        // @ts-ignore
        let title = (nameTitle == "type")?VM_TYPE_MAP[item[nameTitle]]:item[nameTitle];
        return {
            ...item,
            title : title+(subtitle?("("+item[subtitle]+")"):""),
            allDuration : Utils.getProbablyTime(item.allDuration),
            minDuration : Utils.getProbablyTime(item.minDuration),
            maxDuration : Utils.getProbablyTime(item.maxDuration),
            avgDuration : Utils.getProbablyTime(item.avgDuration),
            node:{...item,children:[]},
        }
    }

    queryDataByDB(val: SelectionParam | any) {
        this.loadingList.push(1)
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible";
        getTabPaneVirtualMemoryStatisticsData(val.leftNs + val.recordStartNs,val.rightNs + val.recordStartNs).then(result => {
            this.loadingList.splice(0,1)
            if(this.loadingList.length == 0) {
                this.progressEL!.loading = false
                this.loadingPage.style.visibility = "hidden"
            }
            this.resultData = JSON.parse(JSON.stringify(result));
            this.sortStatus(result,"type","ipid")
        })
    }

    sortStatus(result:Array<any>,firstLevel:string,secondLevel:string){
        let fatherMap = new Map<any,any>();
        let childMap = new Map<any,any>();
        let allNode:any = {
            title:"All",
            count:0,
            allDuration:0,
            minDuration:0,
            maxDuration:0,
            avgDuration:"",
            children:[],
        };
        result.forEach((item,idx)=>{
            if (childMap.has(item[firstLevel]+"_"+item[secondLevel])) {
                let obj1 = childMap.get(item[firstLevel]+"_"+item[secondLevel]);
                obj1.count += item.count;
                obj1.allDuration += item.allDuration;
                obj1.minDuration = obj1.minDuration<=item.minDuration?obj1.minDuration:item.minDuration;
                obj1.maxDuration = obj1.maxDuration>=item.maxDuration?obj1.maxDuration:item.maxDuration;
                obj1.children.push(this.getInitData(item,firstLevel=="type"?"tname":"type",firstLevel=="type"?"tid":null));
            }else {
                childMap.set(item[firstLevel]+"_"+item[secondLevel],{
                    ...item,
                    children:[this.getInitData(item,firstLevel=="type"?"tname":"type",firstLevel=="type"?"tid":null)]
                })
            }

            if (fatherMap.has(item[firstLevel])) {
                let obj1 = fatherMap.get(item[firstLevel]);
                obj1.count += item.count;
                obj1.allDuration += item.allDuration;
                obj1.minDuration = obj1.minDuration<=item.minDuration?obj1.minDuration:item.minDuration;
                obj1.maxDuration = obj1.maxDuration>=item.maxDuration?obj1.maxDuration:item.maxDuration;
                obj1.children.push(this.getInitData(item));
            }else {
                fatherMap.set(item[firstLevel],{
                    ...item,
                    children:[this.getInitData(item)]
                })
            }
            if (idx == 0) {
                allNode.minDuration = item.minDuration;
            }else {
                allNode.minDuration = allNode.minDuration<=item.minDuration?allNode.minDuration:item.minDuration;
            }
            allNode.count += item.count;
            allNode.allDuration += item.allDuration;
            allNode.maxDuration = allNode.maxDuration>=item.maxDuration?allNode.maxDuration:item.maxDuration;
        })

        for (let ks of fatherMap.keys()) {
            let sp = fatherMap.get(ks)
            sp!.children = [];
            sp.avgDuration = sp.allDuration/sp.count;
            let node = this.getInitData(sp,firstLevel=="type"?"type":"pname",firstLevel=="type"?null:"pid");
            node.path = {type:null,tid:null,pid:null,value:node.title}
            node.path[firstLevel=="type"?"type":"pid"] = node[firstLevel=="type"?"type":"pid"];
            for (let kst of childMap.keys()) {
                if (kst.startsWith(ks + "_")) {
                    let spt = childMap.get(kst)
                    let data = this.getInitData(spt!,firstLevel=="type"?"pname":"tname",firstLevel=="type"?"pid":"tid")
                    data.path = {type:null,tid:null,pid:null,value:"All-"+node.title+"-"+data.title}
                    data.path[firstLevel=="type"?"type":"pid"] = node[firstLevel=="type"?"type":"pid"];
                    data.path[firstLevel=="type"?"pid":"tid"] = data[firstLevel=="type"?"pid":"tid"];
                    data.children.forEach((e:any)=>{
                        e.path = {type:null,tid:null,pid:null,value:"All-"+node.title+"-"+data.title+"-"+e.title}
                        e.path[firstLevel=="type"?"type":"pid"] = node[firstLevel=="type"?"type":"pid"];
                        e.path[firstLevel=="type"?"pid":"tid"] = data[firstLevel=="type"?"pid":"tid"];
                        e.path[firstLevel=="type"?"tid":"type"] = e[firstLevel=="type"?"tid":"type"];
                    })
                    sp!.children.push(data);
                }
            }
            allNode.children.push(node)
        }

        allNode.avgDuration = allNode.allDuration/allNode.count;
        allNode = this.getInitData(allNode);
        allNode.title = "All";
        allNode.path = {type:null,tid:null,pid:null,value:"All"};
        this.source = result.length > 0 ? [allNode] : [];
        let newSource = JSON.parse(JSON.stringify(this.source));
        if (this.sortType != 0 && result.length > 0) this.sortTable(newSource[0],this.sortKey);
        this.tbl!.recycleDataSource = newSource;
    }

    sortTable(allNode:any,key:string){
        allNode.children.sort((a:any, b:any) => {
            if (this.sortType == 1) {
                return a.node[key] - b.node[key]
            }else if (this.sortType == 2) {
                return b.node[key] - a.node[key]
            }
        });
        allNode.children.forEach((item:any)=>{
            item.children.sort((a:any, b:any) => {
                if (this.sortType == 1) {
                    return a.node[key] - b.node[key]
                }else if (this.sortType == 2) {
                    return b.node[key] - a.node[key]
                }
            })
            item.children.forEach((i:any)=>{
                i.children.sort((a:any, b:any) => {
                    if (this.sortType == 1) {
                        return a.node[key] - b.node[key]
                    }else if (this.sortType == 2) {
                        return b.node[key] - a.node[key]
                    }
                })
            });
        });
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
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
        <lit-table id="tb-states" style="height: auto" tree>
            <lit-table-column width="20%" title="Operation/Process/Thread" data-index="title" key="title" align="flex-start">
            </lit-table-column>
            <lit-table-column width="1fr" title="Count" data-index="count" key="count" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Duration" data-index="allDuration" key="allDuration" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Min Duration" data-index="minDuration" key="minDuration" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Avg Duration" data-index="avgDuration" key="avgDuration" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Max Duration" data-index="maxDuration" key="maxDuration" align="flex-start" order>
            </lit-table-column>
        </lit-table>
        <lit-progress-bar class="progress"></lit-progress-bar>
        <tab-pane-filter id="filter" sort></tab-pane-filter>
        <div class="loading"></div>
        `;
    }
}
