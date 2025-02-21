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
import {SpHiSysEventChart} from "../../../chart/SpHiSysEventChart.js";
import {LitTable} from "../../../../../base-ui/table/lit-table.js";

import {
    queryAnomalyDetailedData
} from "../../../../database/SqlLite.js";
import {SelectionParam} from "../../../../bean/BoxSelection.js";
import {EnergyAnomalyStruct} from "../../../../bean/EnergyStruct.js";

@element('tabpane-anomaly-details')
export class TabPaneEnergyAnomaly extends BaseElement {
    private tbl: LitTable | null | undefined;
    private tableObserver: MutationObserver | undefined

    set data(selection: SelectionParam) {
        let div: HTMLElement | null | undefined = this?.shadowRoot?.querySelector("#anomaly-details");
        let htmlText = "";
        if(selection){
            this.queryAnomalyTableData(selection.leftNs, selection.rightNs).then((bean) => {
                let filterAppMap = new Map();
                for(let index = 0;index < bean.length;index++){
                    let findAppNameIndex = -1;
                    let values = Object.values(bean[index]);
                    if(values[3]){
                        let apps = values[3].split(',');
                        for(let appIndex = 0;appIndex < apps.length;appIndex++){
                            if(apps.indexOf(SpHiSysEventChart.app_name) != -1){
                                findAppNameIndex = apps.indexOf(SpHiSysEventChart.app_name);
                                filterAppMap.set(values[0] + values[1], findAppNameIndex);
                                break;
                            }
                        }
                        if(values[2] == 'APPNAME'){
                            //ts+eventName : appNameIndex
                            filterAppMap.set(values[0] + values[1], findAppNameIndex);
                        }
                    }
                }
                let set = new Set();
                for(let index = 0;index < bean.length;index++){
                    let values = Object.values(bean[index]);
                    let findAppNameIndex = -1;
                    if(filterAppMap.get(values[0] + values[1]) == -1){
                        continue
                    }else {
                        findAppNameIndex = filterAppMap.get(values[0] + values[1]);
                    }
                    if(!set.has(values[0])){
                        set.add(values[0]);
                        htmlText += "<div><table" +
                            " style='border:none;table-layout:fixed;word-break:break-all' cellspacing=\"5\"; cellpadding=\"5\"><tbody>" +
                            "<tr><td colspan=\"5\" style='font-weight: 700;font-size: 14px'>"+values[1]+"</td></tr>";
                    }
                    if(set.has(Object.values(bean[index])[0])){
                        let appValues = values[3].split(',');
                        htmlText += "<tr><td style='font-weight: 400;font-size: 14px;opacity:0.9;width:150px;'>"+values[2]
                            +"</td><td style='font-weight: 400;font-size: 14px;opacity:0.6;width:250px;'>"+
                            (findAppNameIndex >= 0 ? appValues.length > 1 ? appValues[findAppNameIndex] : values[3] : values[3])
                            +"</td><td style='width:100px'></td>";
                    }
                    if(index + 1 < bean.length){
                        let nextValues = Object.values(bean[index + 1]);
                        let appValues = nextValues[3].split(',');
                        if(set.has(nextValues[0])){
                            htmlText += "<td style='font-weight: 400;font-size: 14px;opacity:0.9;width:150px;'>" + nextValues[2]
                                + "</td><td style='font-weight: 400;font-size: 14px;opacity:0.6;width:250px;'>" +
                                (findAppNameIndex >= 0 ? appValues.length > 1 ? appValues[findAppNameIndex] : nextValues[3] : nextValues[3])
                                +"</td></tr>";
                        } else {
                            htmlText += "</tr>";
                            htmlText += "</tbody></table></div>";
                            continue;
                        }
                        index++;
                    }
                }
                div!.innerHTML = htmlText;
            })
        }
    }

    /**
     * 查询出 异常详细信息
     * @param data
     */
    async queryAnomalyTableData(startTime: number, endTime: number) : Promise<Array<EnergyAnomalyStruct>> {
        let anomalyTableData = await queryAnomalyDetailedData(startTime, endTime)
       return anomalyTableData;
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#anomalyselectionTbl');
        this.tbl?.addEventListener("column-click", (ev: any) => {
        })
        this.addTableObserver()
    }

    connectedCallback() {
        super.connectedCallback();
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl!.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl!.reMeauseHeight()
            }
        }).observe(this.parentElement!);
    }

    addTableObserver() {
        let MutationObserver = window.MutationObserver
        this.tableObserver = new MutationObserver((list) => {
            if (this.tbl) {
                let width = getComputedStyle(this.tbl).getPropertyValue("width")
                let height = getComputedStyle(this.tbl).getPropertyValue("height")
            }
        })
        let selector = this.shadowRoot?.querySelector(".left-table");
        this.tableObserver?.observe(selector!, {attributes: true, attributeFilter: ['style'], attributeOldValue: true})
    }

    initHtml(): string {
        return `
        <style>
            .current-title{
                width: 95%;
                display: flex;
                top: 0;
                background: var(--dark-background,#ffffff);
                position: sticky;
            }
            .current-title h2{
                width: 50%;
                padding: 0 10px;
                font-size: 16px;
                font-weight: 400;
                visibility: visible;
            }
            .bottom-scroll-area{
                display: flex;
                height: auto;
                overflow-y: auto;
            }
            .left-table{
                width: 50%;
                padding: 0 10px;
            }
        </style>
        <div style="width: 100%;height: auto;position: relative">
            <div id="anomaly-details" class="current-title" style="margin-left: 12px;display: block">
                <h2 id="leftTitle"></h2>
            </div>
            <div class="bottom-scroll-area">
                <div class="left-table">
                    <lit-table id="anomalyselectionTbl" no-head style="height: auto">
                        <lit-table-column title="name" data-index="name" key="name" align="flex-start"  width="180px">
                        </lit-table-column>
                        <lit-table-column title="value" data-index="value" key="value" align="flex-start" >
                        </lit-table-column>
                    </lit-table>
                </div>
            </div>
        </div>
        `;
    }
}
