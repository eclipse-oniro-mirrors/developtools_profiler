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
import {getTabPowerDetailsData} from "../../../../database/SqlLite.js";
import {log} from "../../../../../log/Log.js";
import {PowerDetailsEnergy} from "../../../../bean/EnergyStruct.js";
import {SpHiSysEventChart} from "../../../chart/SpHiSysEventChart.js";

@element('tabpane-power-details')
export class TabPanePowerDetails extends BaseElement {
    private tbl: LitTable | null | undefined;
    private source: Array<any> = [];
    private itemType: any

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
        this.tbl = this.shadowRoot?.querySelector<LitTable>('#tb-power-details-energy');
        this.tbl!.addEventListener('column-click', (evt) => {
            // @ts-ignore
            this.sortByColumn(evt.detail)
        });
        this.source = []
        this.itemType = {
            "time_type": ["foreground_duration", "background_duration", "screen_on_duration", "screen_off_duration",
                "foreground_count", "background_count", "screen_on_count", "screen_off_count", "duration", "energy",
                "usage", "camera_id"],
            "duration_type": ["background_time", "screen_on_time", "screen_off_time", "load", "uid", "usage", "charge",
                "foreground_count", "background_count", "screen_on_count", "screen_off_count", "energy", "duration"],
            "energy_type": ["background_time", "screen_on_time", "screen_off_time", "load", "charge",
                "foreground_count", "background_count", "screen_on_count", "screen_off_count", "camera_id", "uid",
                "foreground_duration", "foreground_energy", "background_duration", "background_energy",
                "screen_on_duration", "screen_on_energy", "screen_off_duration", "screen_off_energy"],
            "count_type": ["background_time", "screen_on_time", "screen_off_time", "load", "energy", "usage",
                "foreground_duration", "background_duration", "screen_on_duration", "screen_off_duration",
                "camera_id", "uid", "duration", "charge"]
        }
    }

    queryDataByDB(val: SelectionParam | any) {
        getTabPowerDetailsData(val.leftNs - val.leftNs, val.rightNs).then(items => {
            log("getTabPowerDetailsData size :" + items.length);
            let detailsData: Array<any> = []
            let set = new Set()
            set.add("COUNT")
            set.add("LOAD")
            set.add("CHARGE")
            set.add("CAMERA_ID")

            let powerData: any = {
                "POWER_IDE_CPU": new PowerDetailsEnergy("CPU"),
                "POWER_IDE_LOCATION": new PowerDetailsEnergy("LOCATION"),
                "POWER_IDE_GPU": new PowerDetailsEnergy("GPU"),
                "POWER_IDE_DISPLAY": new PowerDetailsEnergy("DISPLAY"),
                "POWER_IDE_CAMERA": new PowerDetailsEnergy("CAMERA"),
                "POWER_IDE_BLUETOOTH": new PowerDetailsEnergy("BLUETOOTH"),
                "POWER_IDE_FLASHLIGHT": new PowerDetailsEnergy("FLASHLIGHT"),
                "POWER_IDE_AUDIO": new PowerDetailsEnergy("AUDIO"),
                "POWER_IDE_WIFISCAN": new PowerDetailsEnergy("WIFISCAN")
            };
            let tsMax = 0
            let currentAppIndex = -1
            items.forEach(item => {
                let powerDatum: any = powerData[item.eventName];
                if (item.appKey.toLocaleLowerCase() === "appname") {
                    powerDatum['appName'] = SpHiSysEventChart.app_name
                    currentAppIndex = item.eventValue.split(",").indexOf(SpHiSysEventChart.app_name!);
                    tsMax = 0
                } else if (currentAppIndex > -1) {
                    if (set.has(item.appKey)) {
                        if (item.startNS >= tsMax) {
                            powerDatum[item.appKey.toLocaleLowerCase()] = item.eventValue
                            tsMax = item.startNS
                        }
                    } else {
                        powerDatum[item.appKey.toLocaleLowerCase()] += parseInt(item.eventValue.split(",")[currentAppIndex])
                    }
                }
            })

            let totalEnergy = powerData["POWER_IDE_CPU"].getTotalEnergy(false)
                + powerData["POWER_IDE_LOCATION"].getTotalEnergy(false)
                + powerData["POWER_IDE_GPU"].getTotalEnergy(true)
                + powerData["POWER_IDE_DISPLAY"].getTotalEnergy(true)
                + powerData["POWER_IDE_CAMERA"].getTotalEnergy(false)
                + powerData["POWER_IDE_BLUETOOTH"].getTotalEnergy(false)
                + powerData["POWER_IDE_FLASHLIGHT"].getTotalEnergy(false)
                + powerData["POWER_IDE_AUDIO"].getTotalEnergy(false)
                + powerData["POWER_IDE_WIFISCAN"].getTotalEnergy(false)

            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_CPU", false, "time_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_LOCATION", false, "duration_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_GPU", true, "energy_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_DISPLAY", true, "energy_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_CAMERA", false, "duration_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_BLUETOOTH", false, "duration_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_FLASHLIGHT", false, "duration_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_AUDIO", false, "duration_type"))
            detailsData.push(this.setEnergyItems(powerData, totalEnergy, "POWER_IDE_WIFISCAN", false, "count_type"))

            if (detailsData.length > 0) {
                this.source = detailsData
                this.tbl!.recycleDataSource = detailsData
            } else {
                this.source = []
                this.tbl!.recycleDataSource = []
            }
            this.tbl?.shadowRoot?.querySelectorAll<HTMLDivElement>(".td").forEach(td => {
                td.style.fontSize = "14px"
                td.style.fontWeight = "400"
                td.style.opacity = '0.9'
                td.style.lineHeight = "16px"
            })
        })
        let th = this.tbl?.shadowRoot?.querySelector<HTMLDivElement>(".th")
        if (th) {
            th!.style.gridColumnGap = "5px";
        }
    }

    setEnergyItems(powerData: any, totalEnergy: number, energyName: string, isSimpleEnergy: boolean, type: any): any {
        let ratio = powerData[energyName]
            .getTotalEnergy(isSimpleEnergy) * 100 / totalEnergy
        if (totalEnergy == 0) {
            powerData[energyName].energyConsumptionRatio = "0.000 %"
        } else {
            powerData[energyName].energyConsumptionRatio = ratio.toFixed(3) + " %"
        }
        return this.getEnergyStyle(powerData, energyName, type)
    }

    getEnergyStyle(powerData: any, energyName: string, type: any) {
        this.itemType[type].forEach((item: any) => {
            powerData[energyName][item] = "-"
        })
        if (type === "energy_type") {
            if (energyName == "POWER_IDE_GPU") {
                powerData[energyName]["duration"] = "-"
            } else {
                powerData[energyName]["usage"] = "-"
            }
        } else if (type === "duration_type") {
            if (energyName != "POWER_IDE_CAMERA") {
                powerData[energyName]["camera_id"] = "-"
            }
        }
        return powerData[energyName]
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
        <lit-table id="tb-power-details-energy" style="height: auto">
            <lit-table-column order width="100px" title="" data-index="event" key="event" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="60px" title="UId" data-index="uid" key="uid" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="80px" title="Charge" data-index="charge" key="charge" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Foreground Duration" data-index="foreground_duration" key="foreground_duration" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Foreground Energy" data-index="foreground_energy" key="foreground_energy" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Background Duration" data-index="background_duration" key="background_duration" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Background Energy" data-index="background_energy" key="background_energy" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen On Duration" data-index="screen_on_duration" key="screen_on_duration" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen On Energy" data-index="screen_on_energy" key="screen_on_energy" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen Off Duration" data-index="screen_off_duration" key="screen_off_duration" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen Off Energy" data-index="screen_off_energy" key="screen_off_energy" align="flex-start" >
            </lit-table-column>
             <lit-table-column order width="180px" title="Foreground Count" data-index="foreground_count" key="foreground_count" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Background Count" data-index="background_count" key="background_count" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen On Count" data-index="screen_on_count" key="screen_on_count" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen Off Count" data-index="screen_off_count" key="screen_off_count" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Background Time" data-index="background_time" key="background_time" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen On Time" data-index="screen_on_time" key="screen_on_time" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="180px" title="Screen Off Time" data-index="screen_off_time" key="screen_off_time" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="80px" title="Energy" data-index="energy" key="energy" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="80px" title="Load" data-index="load" key="load" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="80px" title="Usage" data-index="usage" key="usage" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="80px" title="Duration" data-index="duration" key="duration" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="100px" title="Camera Id" data-index="camera_id" key="camera_id" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="80px" title="Count" data-index="count" key="count" align="flex-start" >
            </lit-table-column>
            <lit-table-column order width="200px" title="energyPercent" data-index="energyConsumptionRatio" key="energyConsumptionRatio" align="flex-start" >
            </lit-table-column>
        </lit-table>
        `;
    }

    sortByColumn(detail: any) {
        // @ts-ignore
        function compare(property, sort, type) {
            return function (a: PowerDetailsEnergy, b: PowerDetailsEnergy) {
                if (type === 'number') {
                    // @ts-ignore
                    return sort === 2 ? parseFloat(b[property] == "-" ? 0 : b[property]) - parseFloat(a[property] == "-" ? 0 : a[property]) : parseFloat(a[property] == "-" ? 0 : a[property]) - parseFloat(b[property] == "-" ? 0 : b[property]);
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

        if (detail.key === 'appName') {
            this.source.sort(compare(detail.key, detail.sort, 'string'))
        } else {
            this.source.sort(compare(detail.key, detail.sort, 'number'))
        }
        this.tbl!.recycleDataSource = this.source;
    }
}
