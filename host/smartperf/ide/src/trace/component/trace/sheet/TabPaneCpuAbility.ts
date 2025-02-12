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

import {BaseElement, element} from "../../../../base-ui/BaseElement.js";
import {LitTable} from "../../../../base-ui/table/lit-table.js";
import {SelectionParam} from "../../../bean/BoxSelection.js";
import {getTabCpuAbilityData,} from "../../../database/SqlLite.js";
import {SystemCpuSummary} from "../../../bean/AbilityMonitor.js";
import {Utils} from "../base/Utils.js";
import {ColorUtils} from "../base/ColorUtils.js";
import "../../../component/SpFilter.js";
import {log} from "../../../../log/Log.js";

@element('tabpane-cpu-ability')
export class TabPaneCpuAbility extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<SystemCpuSummary> = [];
    private queryResult: Array<SystemCpuSummary> = []
    private float: HTMLDivElement | null | undefined;
    private search: HTMLInputElement | undefined | null

    set data(val: SelectionParam | any) {
        // @ts-ignore
        this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
        this.queryDataByDB(val)
    }

    initElements(): void {
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-cpu-ability');
        new ResizeObserver((entries) => {
            if (this.parentElement?.clientHeight != 0) {
                // @ts-ignore
                this.tbl?.shadowRoot.querySelector(".table").style.height = (this.parentElement.clientHeight - 45) + "px"
                this.tbl?.reMeauseHeight()
            }
        }).observe(this.parentElement!)
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail)
        });
    }

    filterData() {
        if (this.queryResult.length > 0) {
            let filter = this.queryResult.filter((item) => {
                let array = this.toCpuAbilityArray(item)
                let isInclude = array.filter(value => value.indexOf(this.search!.value) > -1);
                return isInclude.length > 0
            });
            if (filter.length > 0) {
                this.source = filter;
                this.tbl!.recycleDataSource = this.source;
            } else {
                this.source = []
                this.tbl!.recycleDataSource = [];
            }
        }
    }

    toCpuAbilityArray(systemCpuSummary: SystemCpuSummary): any[] {
        let array: Array<string> = []
        array.push(systemCpuSummary.startTimeStr)
        array.push(systemCpuSummary.durationStr)
        array.push(systemCpuSummary.totalLoadStr)
        array.push(systemCpuSummary.userLoadStr)
        array.push(systemCpuSummary.systemLoadStr)
        array.push(systemCpuSummary.threadsStr)
        return array
    }

    queryDataByDB(val: SelectionParam | any) {
        getTabCpuAbilityData(val.leftNs, val.rightNs).then(result => {
            log("getTabCpuAbilityData size :" + result.length);
            if (result.length != null && result.length > 0) {
                for (const systemCpuSummary of result) {
                    if (systemCpuSummary.startTime == 0) {
                        systemCpuSummary.startTimeStr = '0:000.000.000';
                    } else {
                        systemCpuSummary.startTimeStr = Utils.getTimeStampHMS(systemCpuSummary.startTime);
                    }
                    systemCpuSummary.durationStr = Utils.getDurString(systemCpuSummary.duration);
                    systemCpuSummary.totalLoadStr = (systemCpuSummary.totalLoad).toFixed(2) + "%"
                    systemCpuSummary.userLoadStr = (systemCpuSummary.userLoad).toFixed(2) + "%"
                    systemCpuSummary.systemLoadStr = (systemCpuSummary.systemLoad).toFixed(2) + "%"
                    systemCpuSummary.threadsStr = ColorUtils.formatNumberComma(systemCpuSummary.threads);
                }
                this.source = result
                this.queryResult = result;
                this.tbl!.recycleDataSource = this.source
            } else {
                this.source = []
                this.queryResult = []
                this.tbl!.recycleDataSource = []
            }
        })
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: flex;
            flex-direction: column;
            padding: 10px 10px;
        }

        </style>
        <lit-table id="tb-cpu-ability" style="height: auto">
            <lit-table-column order width="1fr" title="Start Time" data-index="startTimeStr" key="startTimeStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Duration" data-index="durationStr" key="durationStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="TotalLoad %" data-index="totalLoadStr" key="totalLoadStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="UserLoad %" data-index="userLoadStr" key="userLoadStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="SystemLoad %" data-index="systemLoadStr" key="systemLoadStr" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="1fr" title="Process" data-index="threadsStr" key="threadsStr" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: SystemCpuSummary, b: SystemCpuSummary) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property]) - parseFloat(a[property]) : parseFloat(a[property]) - parseFloat(b[property]);
                } else if (type === 'durationStr') {
                    return sort === 2 ? b.duration - a.duration : a.duration - b.duration;
                } else if (type === 'totalLoadStr') {
                    return sort === 2 ? b.totalLoad - a.totalLoad : a.totalLoad - b.totalLoad;
                } else if (type === 'userLoadStr') {
                    return sort === 2 ? b.userLoad - a.userLoad : a.userLoad - b.userLoad;
                } else if (type === 'systemLoadStr') {
                    return sort === 2 ? b.systemLoad - a.systemLoad : a.systemLoad - b.systemLoad;
                } else {
                    // @ts-ignore
                    if (b[property] > a[property]) {
                        return sort === 2 ? 1 : -1;
                    } else { // @ts-ignore
                        if (b[property] == a[property]) {
                            return 0;
                        } else {
                            return sort === 2 ? -1 : 1;
                        }
                    }
                }
            }
        }

        if (detail.key === 'startTime') {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else if (detail.key === 'durationStr') {
            this.source.sort(compare(detail.key, detail.sort, 'durationStr'))
        } else if (detail.key === 'totalLoadStr') {
            this.source.sort(compare(detail.key, detail.sort, 'totalLoadStr'))
        } else if (detail.key === 'userLoadStr') {
            this.source.sort(compare(detail.key, detail.sort, 'userLoadStr'))
        } else if (detail.key === 'systemLoadStr') {
            this.source.sort(compare(detail.key, detail.sort, 'systemLoadStr'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }

}