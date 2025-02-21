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
import {LitProgressBar} from "../../../../../base-ui/progress-bar/LitProgressBar.js";
import {Utils} from "../../base/Utils.js";
import {ColorUtils} from "../../base/ColorUtils.js";
import {CpuFreqLimitsStruct} from "../../../../database/ui-worker/ProcedureWorkerCpuFreqLimits.js";

@element('tabpane-cpu-freq-limits')
export class TabPaneCpuFreqLimits extends BaseElement {
    private tbl: LitTable | null | undefined;
    private range: HTMLLabelElement | null | undefined;
    private loadDataInCache: boolean = true;
    private selectionParam:SelectionParam | null | undefined;
    private source:CpuFreqLimit[] = []
    private sortKey: string = "cpu";
    private sortType: number = 0;

    set data(val: SelectionParam | any) {
        if(val == this.selectionParam){
            return;
        }
        this.selectionParam = val;
        // @ts-ignore
        this.tbl!.shadowRoot!.querySelector(".table").style.height = (this.parentElement!.clientHeight - 25) + "px"
        let list:any[] = []
        val.cpuFreqLimitDatas.forEach((limitRowDatas:any)=>{
            for (let i = 0, len = limitRowDatas.length; i < len; i++) {
                let it = limitRowDatas[i];
                if(it.startNs > val.rightNs){
                    break;
                }
                if (i === limitRowDatas.length - 1) {
                    it.dur = (val.rightNs || 0) - (it.startNs || 0)
                } else {
                    it.dur = (limitRowDatas[i + 1].startNs || 0) - (it.startNs || 0)
                }
                list.push(it)
            }
        })
        this.formatData(list,val.leftNs,val.rightNs)
    }

    initElements(): void {
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
            }
        }).observe(this.parentElement!);
    }

    formatData(list:CpuFreqLimitsStruct[],start:number,end:number){
        let limitsMap = new Map<string,CpuFreqLimit>();
        let groupMapData = (time:number,id:string,item:CpuFreqLimitsStruct) => {
            if (limitsMap.has(id)) {
                limitsMap.get(id)!.time += (time)
            }else {
                let isMax = id.endsWith("max");
                let limit = new CpuFreqLimit();
                limit.cpu = `Cpu ${item.cpu}`;
                limit.time = time;
                limit.type = isMax?"Max Freqency":"Min Frequency"
                limit.value = isMax?item.max!:item.min!;
                limitsMap.set(id,limit)
            }
        }
        list.forEach((item)=>{
            if(item.startNs!>end){
                return
            }
            let max = Math.max(item.startNs||0,start)
            let min = Math.min((item.startNs||0)+item.dur,end)
            if(max < min){
                let maxId = `${item.cpu}-${item.max}-max`
                let minId = `${item.cpu}-${item.min}-min`
                groupMapData(min - max,maxId,item)
                groupMapData(min - max,minId,item)
            }
        })
        this.source =  Array.from(limitsMap.values()).map((item) => {
            item.timeStr = Utils.getProbablyTime(item.time);
            item.valueStr = `${ColorUtils.formatNumberComma(item.value!)} kHz`
            return item
        })
        this.sortTable(this.sortKey,this.sortType)
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
                }else if(key == "valueStr"){
                    if(type == 1){
                        return a.value - b.value ;
                    }else{
                        return b.value - a.value ;
                    }
                }else if(key == "cpu"){
                    if (a.cpu > b.cpu) {
                        return type === 2 ? -1 : 1;
                    } else if (a.cpu == b.cpu)  {
                        return 0;
                    } else {
                        return type === 2 ? 1 : -1;
                    }
                }else if(key == "type"){
                    if (a.type > b.type) {
                        return type === 2 ? 1 : -1;
                    } else if (a.type == b.type)  {
                        return 0;
                    } else {
                        return type === 2 ? -1 : 1;
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
            <lit-table-column width="20%" title="Cpu" data-index="cpu" key="cpu" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Type" data-index="type" key="type" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Time" data-index="timeStr" key="timeStr" align="flex-start" order>
            </lit-table-column>
            <lit-table-column width="1fr" title="Value" data-index="valueStr" key="valueStr" align="flex-start" order>
            </lit-table-column>
        </lit-table>
        `;
    }
}

class CpuFreqLimit{
    cpu:string = "";
    type:string = "";
    time:number = 0;
    value:number = 0;
    timeStr:string = "";
    valueStr:string = "";

}
