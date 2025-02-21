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
import {query, queryNativeHookEventTid} from "../../../../database/SqlLite.js";
import {NativeHookCallInfo, NativeHookStatistics} from "../../../../bean/NativeHook.js";
import "../TabPaneFilter.js"
import {FilterData, TabPaneFilter} from "../TabPaneFilter.js";
import "../../../chart/FrameChart.js";
import "../../../../../base-ui/slicer/lit-slicer.js";
import {FrameChart} from "../../../chart/FrameChart.js";
import {ChartMode} from "../../../../bean/FrameChartStruct.js";
import {LitProgressBar} from "../../../../../base-ui/progress-bar/LitProgressBar.js";
import {procedurePool} from "../../../../database/Procedure.js";


@element('tabpane-native-callinfo')
export class TabPaneNMCallInfo extends BaseElement {
    private tbl: LitTable | null | undefined;
    private tblData: LitTable | null | undefined;
    private progressEL:LitProgressBar | null | undefined;
    private loadingList:number[] = []
    private loadingPage:any;
    private source: Array<NativeHookCallInfo> = []
    private rightSource: Array<NativeHookCallInfo> = []
    private queryResult: Array<NativeHookStatistics> = []
    private native_type: Array<string> = ["All Heap & Anonymous VM", "All Heap", "All Anonymous VM"];
    private filterAllocationType: string = "0"
    private filterNativeType: string = "0"
    private currentSelection: SelectionParam | undefined
    private frameChart: FrameChart | null | undefined;
    private isChartShow: boolean = false;
    private sortColumn: string = '';
    private sortType: number = 0;

    set data(val: SelectionParam | any) {
        if(val == this.currentSelection){
            return;
        }
        this.currentSelection = val
        this.initFilterTypes()
        let types: Array<string> = []
        if (val.nativeMemory.indexOf(this.native_type[0]) != -1) {
            types.push("'AllocEvent'");
            types.push("'MmapEvent'");
        } else {
            if (val.nativeMemory.indexOf(this.native_type[1]) != -1) {
                types.push("'AllocEvent'");
            }
            if (val.nativeMemory.indexOf(this.native_type[2]) != -1) {
                types.push("'MmapEvent'");
            }
        }
        // @ts-ignore
        this.tbl?.shadowRoot?.querySelector(".table").style.height = (this.parentElement.clientHeight - 20 - 31) + "px"
        // @ts-ignore
        this.tblData?.shadowRoot?.querySelector(".table").style.height = (this.parentElement.clientHeight) + "px"
        // @ts-ignore
        this.tblData?.recycleDataSource = [];
        // @ts-ignore
        this.tbl?.recycleDataSource = [];
        this.progressEL!.loading = true
        this.loadingPage.style.visibility = "visible"
        queryNativeHookEventTid(val.leftNs, val.rightNs, types).then((result) => {
            this.queryResult = result;
            this.getDataByNativeMemoryWorker(val)
        })
    }

    getDataByNativeMemoryWorker(val: SelectionParam | any){
        let args = new Map<string,any>();
        args.set("data",this.queryResult);
        args.set("filterAllocType",this.filterAllocationType);
        args.set("filterEventType",this.filterNativeType);
        args.set("leftNs",val.leftNs);
        args.set("rightNs",val.rightNs);
        args.set("actionType","call-info");
        this.startWorker(args,(results: any[]) => {
            this.tblData!.recycleDataSource = []
            this.progressEL!.loading = false
            if (results.length > 0) {
                this.source = results;
                this.sortTreeByColumn(this.sortColumn,this.sortType);
                this.frameChart!.mode = ChartMode.Byte;
                this.frameChart!.data = this.source;
                this.frameChart?.updateCanvas(true,this.clientWidth);
                this.frameChart?.calculateChartData();
            }else {
                this.source = []
                this.tbl!.recycleDataSource = [];
                this.frameChart!.data = [];
                this.frameChart!.clearCanvas()
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

    getParentTree(src: Array<NativeHookCallInfo>, target: NativeHookCallInfo, parents: Array<NativeHookCallInfo>): boolean {
        for (let hook of src) {
            if (hook.id == target.id) {
                parents.push(hook)
                return true
            } else {
                if (this.getParentTree(hook.children as Array<NativeHookCallInfo>, target, parents)) {
                    parents.push(hook);
                    return true;
                }
            }
        }
        return false;
    }

    getChildTree(src: Array<NativeHookCallInfo>, eventId: number, children: Array<NativeHookCallInfo>): boolean {
        for (let hook of src) {
            if (hook.eventId == eventId && hook.children.length == 0) {
                children.push(hook)
                return true
            } else {
                if (this.getChildTree(hook.children as Array<NativeHookCallInfo>, eventId, children)) {
                    children.push(hook);
                    return true;
                }
            }
        }
        return false;
    }

    setRightTableData(hook: NativeHookCallInfo) {
        let parents: Array<NativeHookCallInfo> = [];
        let children: Array<NativeHookCallInfo> = [];
        this.getParentTree(this.source, hook, parents);
        let maxEventId = hook.eventId;
        let maxHeap = 0;

        function findMaxStack(hook: NativeHookCallInfo) {
            if (hook.children.length == 0) {
                if (hook.size > maxHeap) {
                    maxHeap = hook.size;
                    maxEventId = hook.eventId;
                }
            } else {
                hook.children.map((hookChild) => {
                    findMaxStack(<NativeHookCallInfo>hookChild);
                })
            }
        }

        findMaxStack(hook);
        this.getChildTree(hook.children as Array<NativeHookCallInfo>, maxEventId, children);
        this.rightSource = parents.reverse().concat(children.reverse());
        let len = this.rightSource.length;
        // @ts-ignore
        this.tblData?.dataSource = len == 0 ? [] : this.rightSource.slice(1, len);

    }

    initFilterTypes() {
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")
        this.queryResult = []
        filter!.firstSelect = "0"
        filter!.secondSelect = "0"
        this.filterAllocationType = "0"
        this.filterNativeType = "0"
    }

    sortTreeByColumn(column:string,sort:number){
        this.sortColumn = column;
        this.sortType = sort;
        this.tbl!.recycleDataSource = this.sortTree(this.source,column,sort)
    }

    sortTree(arr: Array<NativeHookCallInfo>, column: string, sort: number): Array<NativeHookCallInfo> {
        let sortArr = arr.sort((a, b) => {
            if (column == 'size') {
                if (sort == 0) {
                    return a.eventId - b.eventId;
                } else if (sort == 1) {
                    return a.size - b.size;
                } else {
                    return b.size - a.size;
                }
            } else {
                if (sort == 0) {
                    return a.eventId - b.eventId;
                } else if (sort == 1) {
                    return a.count - b.count;
                } else {
                    return b.count - a.count;
                }
            }
        })
        sortArr.map((call) => {
            call.children = this.sortTree(call.children as Array<NativeHookCallInfo>, column, sort);
        })
        return sortArr;
    }

    showButtomMenu(isShow : boolean){
        let filter = this.shadowRoot?.querySelector<TabPaneFilter>("#filter")!
        if (isShow) {
            filter.setAttribute('first','');
            filter.setAttribute('second','');
        } else {
            filter.removeAttribute('first');
            filter.removeAttribute('second');
        }
    }

    initElements(): void {
        this.loadingPage = this.shadowRoot?.querySelector('.loading');
        this.progressEL = this.shadowRoot?.querySelector('.progress') as LitProgressBar
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-native-callinfo');
        this.tblData = this.shadowRoot?.querySelector<LitTable>('#tb-native-data');
        this.frameChart = this.shadowRoot?.querySelector<FrameChart>('#framechart');
        let pageTab = this.shadowRoot?.querySelector('#show_table');
        let pageChart = this.shadowRoot?.querySelector('#show_chart');
        this.frameChart?.addChartClickListener((showMenu : boolean) => {
            this.parentElement!.scrollTo(0,0);
            this.showButtomMenu(showMenu)
        });

        this.tbl!.addEventListener("row-click", (e) => {
            // @ts-ignore
            let data = (e.detail.data as NativeHookCallInfo);
            this.setRightTableData(data);
            data.isSelected = true;
            this.tblData?.clearAllSelection(data)
            this.tblData?.setCurrentSelection(data)
            // @ts-ignore
            if ((e.detail as any).callBack) {
                // @ts-ignore
                (e.detail as any).callBack(true)
            }
        })
        this.tblData!.addEventListener("row-click", (e) => {
            // @ts-ignore
            let detail = e.detail.data as NativeHookCallInfo;
            this.tbl?.clearAllSelection(detail)
            detail.isSelected = true
            this.tbl!.scrollToData(detail);
            // @ts-ignore
            if ((e.detail as any).callBack) {
                // @ts-ignore
                (e.detail as any).callBack(true)
            }
        })
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortTreeByColumn((evt.detail.key == "countValue"||evt.detail.key == "countPercent") ? 'countValue':'size',evt.detail.sort)
        });

        this.shadowRoot?.querySelector<TabPaneFilter>("#filter")!.getFilterData((data: FilterData) => {
            this.filterAllocationType = data.firstSelect || "0"
            this.filterNativeType = data.secondSelect || "0"
            this.getDataByNativeMemoryWorker(this.currentSelection)
            if (data.icon == 'block') {
                pageChart?.setAttribute('class', 'show');
                pageTab?.setAttribute('class', '');
                this.isChartShow = true;
                this.frameChart!.data = this.source;
                this.frameChart?.calculateChartData();
            } else if (data.icon == 'tree') {
                pageChart?.setAttribute('class', '');
                pageTab?.setAttribute('class', 'show');
                this.isChartShow = false;
                this.frameChart!.clearCanvas();
                this.tbl!.reMeauseHeight();
            }
        });
        this.initFilterTypes()
    }

    connectedCallback() {
        super.connectedCallback();
        this.parentElement!.onscroll = () => {
            this.frameChart!.tabPaneScrollTop = this.parentElement!.scrollTop;
        };
        let filterHeight = 0;
        new ResizeObserver((entries) => {
            let tabPaneFilter = this.shadowRoot!.querySelector("#filter") as HTMLElement;
            if (tabPaneFilter.clientHeight > 0) filterHeight = tabPaneFilter.clientHeight;
            if (this.parentElement!.clientHeight > filterHeight) {
                tabPaneFilter.style.display = "flex";
            } else {
                tabPaneFilter.style.display = "none";
            }
            if (this.parentElement?.clientHeight != 0) {
                if (!this.isChartShow) {
                    // @ts-ignore
                    this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) + "px"
                    this.tbl?.reMeauseHeight();
                } else {
                    // @ts-ignore
                    this.frameChart?.updateCanvas(false,entries[0].contentRect.width);
                    this.frameChart?.calculateChartData();
                }
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) - 10 - 31 + "px";
                this.tbl?.reMeauseHeight();
                // @ts-ignore
                this.tblData?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight) - 10 - 31 + "px";
                this.tblData?.reMeauseHeight()
                this.loadingPage.style.height = (this.parentElement!.clientHeight - 24) + "px"
            }
        }).observe(this.parentElement!);
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px 0 10px;
        }
        tab-pane-filter {
            border: solid rgb(216,216,216) 1px;
            float: left;
            position: fixed;
            bottom: 0;
            width: 100%;
        }
        selector{
            display: none;
        }
        .progress{
            bottom: 33px;
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
        .show{
            display: flex;
            flex: 1;
        }
        </style>
        <div style="display: flex;flex-direction: row">
            <selector id='show_table' class="show">
            <lit-slicer style="width:100%">
                <div style="width: 65%">
                    <lit-table id="tb-native-callinfo" style="height: auto" tree>
                        <lit-table-column width="60%" title="Symbol Name" data-index="title" key="title"  align="flex-start">
                        </lit-table-column>
                        <lit-table-column width="1fr" title="Size" data-index="heapSizeStr" key="heapSizeStr"  align="flex-start" order>
                        </lit-table-column>
                        <lit-table-column width="1fr" title="%" data-index="heapPercent" key="heapPercent" align="flex-start"  order>
                        </lit-table-column>
                        <lit-table-column width="1fr" title="Count" data-index="countValue" key="countValue" align="flex-start" order>
                        </lit-table-column>
                        <lit-table-column width="1fr" title="%" data-index="countPercent" key="countPercent" align="flex-start" order>
                        </lit-table-column>
                        <lit-table-column width="1fr" title="  " data-index="type" key="type"  align="flex-start" >
                            <template>
                                <img src="img/library.png" size="20" v-if=" type == 1 ">
                                <img src="img/function.png" size="20" v-if=" type == 0 ">
                                <div v-if=" type == - 1 "></div>
                            </template>
                        </lit-table-column>
                    </lit-table>
                </div>
                <lit-slicer-track ></lit-slicer-track>
                <lit-table id="tb-native-data" no-head style="height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)">
                    <lit-table-column width="60px" title="" data-index="type" key="type"  align="flex-start" >
                        <template>
                            <img src="img/library.png" size="20" v-if=" type == 1 ">
                            <img src="img/function.png" size="20" v-if=" type == 0 ">
                        </template>
                    </lit-table-column>
                    <lit-table-column width="1fr" title="" data-index="title" key="title"  align="flex-start">
                    </lit-table-column>
                </lit-table>
                </lit-slicer>
            </selector>
            <selector id='show_chart'>
                <tab-framechart id='framechart' style='width: 100%;height: auto'> </tab-framechart>
            </selector>
            <lit-progress-bar class="progress"></lit-progress-bar>
            <tab-pane-filter id="filter" icon first second></tab-pane-filter>
            <div class="loading"></div>
        </div>
        `;
    }
}
