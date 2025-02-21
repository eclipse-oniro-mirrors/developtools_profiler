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

import {SystemDetailsEnergy} from "../../../../bean/EnergyStruct.js";
import {BaseElement, element} from "../../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../../base-ui/table/lit-table.js";
import {SelectionParam} from "../../../../bean/BoxSelection.js";
import {querySystemDetailsData} from "../../../../database/SqlLite.js";

@element('tabpane-system-details')
export class TabPaneSystemDetails extends BaseElement {
    private tbl: LitTable | null | undefined;
    private detailsTbl: LitTable | null | undefined;
    private eventSource: Array<any> = [];
    private detailsSource: Array<any> = []
    private boxDetails: HTMLDivElement | null | undefined;

    set data(val: SelectionParam | any) {
        this.queryDataByDB(val)
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

    initElements(): void {
        this.boxDetails = this.shadowRoot?.querySelector<HTMLDivElement>('.box-details');
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-system-data');
        this.detailsTbl = this.shadowRoot?.querySelector<LitTable>('#tb-system-details-data');

        this.tbl!.addEventListener('row-click', (e) => {
            this.detailsSource = []
            // @ts-ignore
            let data = (e.detail.data as SystemDetailsEnergy)
            this.convertData(data);
        })

        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail.key, evt.detail.sort)
        });
    }

    convertData(data: SystemDetailsEnergy) {
        if (data.eventName === "Event Name") {
            this.detailsTbl!.recycleDataSource = []
            this.boxDetails!.style.width = "100%"
        } else {
            this.detailsSource.push({key: "EVENT_NAME : ", value: data.eventName})
            this.detailsSource.push({key: "PID : ", value: data.pid})
            this.detailsSource.push({key: "UID : ", value: data.uid})
            if (data.eventName === "GNSS_STATE") {
                this.detailsSource.push({key: "STATE : ", value: data.state})
            } else if (data.eventName === "POWER_RUNNINGLOCK") {
                this.detailsSource.push({key: "TYPE : ", value: data.type})
                this.detailsSource.push({key: "STATE : ", value: data.state})
                this.detailsSource.push({key: "LOG_LEVEL : ", value: data.log_level})
                this.detailsSource.push({key: "NAME : ", value: data.name})
                this.detailsSource.push({key: "MESSAGE : ", value: data.message})
                this.detailsSource.push({key: "TAG : ", value: data.tag})
            } else {
                this.detailsSource.push({key: "TYPE : ", value: data.type})
                this.detailsSource.push({key: "WORK_ID : ", value: data.workId})
                this.detailsSource.push({key: "NAME : ", value: data.name})
                this.detailsSource.push({key: "INTERVAL : ", value: data.interval})
            }
            this.detailsTbl!.recycleDataSource = this.detailsSource
            this.boxDetails!.style.width = "65%"
        }
        this.detailsTbl!.shadowRoot?.querySelectorAll<HTMLDivElement>(".td").forEach(td => {
            let item = td.getAttribute("title");
            td.style.fontSize = "14px"
            td.style.fontWeight = "400"
            if (item != null && item.indexOf(":") > -1) {
                td.style.opacity = "0.9"
                td.style.lineHeight = "16px"
            } else {
                td.style.opacity = "0.6"
                td.style.lineHeight = "20px"
            }
        })
    }

    queryDataByDB(val: SelectionParam | any) {
        querySystemDetailsData(val.leftNs, val.rightNs).then(result => {
            let itemList = []
            let it: any = {}
            result.forEach((item: any) => {
                if (it[item.ts + item.eventName] == undefined) {
                    it[item.ts + item.eventName] = {}
                    it[item.ts + item.eventName]["ts"] = item.ts
                    it[item.ts + item.eventName]["eventName"] = item.eventName
                } else {
                    it[item.ts + item.eventName][item.appKey.toLocaleLowerCase()] = item.appValue
                }
            })
            this.eventSource = []
            let value = Object.values(it);
            this.eventSource.push({
                ts: "Time",
                interval: 0,
                level: 0,
                name: "",
                state: 0,
                tag: "",
                type: "",
                uid: 0,
                pid: 0,
                workId: "",
                message: "",
                log_level: "",
                eventName: "Event Name"
            })
            this.tbl!.recycleDataSource = this.eventSource.concat(value)
            this.detailsTbl!.recycleDataSource = []
            this.boxDetails!.style.width = "100%"
            this.tbl?.shadowRoot?.querySelectorAll<HTMLDivElement>(".td").forEach(td => {
                td.style.fontSize = "14px"
                if (td.getAttribute("title") === "Event Name" || td.getAttribute("title") === "Time") {
                    td.style.fontWeight = "700"
                } else {
                    td.style.fontWeight = "400"
                    td.style.opacity = '0.9'
                    td.style.lineHeight = "16px"
                }
            })
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
        .progress{
            bottom: 33px;
            position: absolute;
            height: 1px;
            left: 0;
            right: 0;
        }
        </style>
        <div style="display: flex;flex-direction: column">
            <div style="display: flex;flex-direction: row">
                <lit-slicer style="width:100%">
                    <div class="box-details" style="width: 100%">
                        <lit-table id="tb-system-data" style="height: auto">
                            <lit-table-column width="300px" title="" data-index="eventName" key="eventName"  align="flex-start" order>
                            </lit-table-column>
                            <lit-table-column width="300px" title="" data-index="ts" key="ts"  align="flex-start" order>
                            </lit-table-column>
                        </lit-table>
                    </div>
                    <lit-slicer-track ></lit-slicer-track>
                    <lit-table id="tb-system-details-data" no-head style="height: auto;border-left: 1px solid var(--dark-border1,#e2e2e2)">
                        <lit-table-column width="100px" title="" data-index="key" key="key"  align="flex-start" >
                        </lit-table-column>
                        <lit-table-column width="1fr" title="" data-index="value" key="value"  align="flex-start">
                        </lit-table-column>
                    </lit-table>
                </lit-slicer>
            </div>
            <lit-progress-bar class="progress"></lit-progress-bar>
        </div>
        `;
    }
}
