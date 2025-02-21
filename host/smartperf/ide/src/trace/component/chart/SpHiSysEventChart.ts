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

import {SpSystemTrace} from "../SpSystemTrace.js";
import {
    queryAnomalyData, queryHisystemEventExits, queryMaxStateValue, queryPowerData, querySmapsExits,
    queryStateData, querySyseventAppName,
    querySystemData
} from "../../database/SqlLite.js";
import {info} from "../../../log/Log.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {procedurePool} from "../../database/Procedure.js";
import {Utils} from "../trace/base/Utils.js";
import {
    EnergyAnomalyStruct,
    EnergyPowerStruct,
    EnergyStateStruct,
    EnergySystemStruct
} from "../../bean/EnergyStruct.js";
import {BaseStruct} from "../../bean/BaseStruct.js";
import {LitPopover} from "../../../base-ui/popover/LitPopoverV.js";

export class SpHiSysEventChart {
    static app_name: string | null
    private trace: SpSystemTrace;
    private energyTraceRow: TraceRow<BaseStruct> | undefined;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    async init() {
        let result = await queryHisystemEventExits();
        if (result.length <= 0) return;
        await this.initEnergyRow();
        await this.initAnomaly();
        await this.initSystem();
        await this.initPower();
        await this.initState();
    }

    private initEnergyRow = async () => {
        let appNameFromTable = await querySyseventAppName();
        if (appNameFromTable.length > 0) {
            SpHiSysEventChart.app_name = appNameFromTable[0].string_value;
        }
        this.energyTraceRow = new TraceRow<BaseStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        let radioList;
        let appNameList = this.energyTraceRow?.shadowRoot!.querySelector<LitPopover>("#appNameList");
        let addFlag = false;
        appNameList?.addEventListener('click', () => {
            let itemDiv = appNameList!.querySelector("div");
            if (!addFlag) {
                for (let index = 0; index < appNameFromTable.length; index++) {
                    let div = document.createElement("div");
                    div.setAttribute("style", "margin-bottom: 5px");
                    let appName = appNameFromTable[index].string_value;
                    // @ts-ignore
                    let formatAppName = "appName" + index;
                    div.setAttribute("id", formatAppName);
                    div.innerHTML = "<input class='radio'  name='processoption' " + (index == 0 ? "checked" : "") + " type='radio'" +
                        " app_name=" + formatAppName + " value= " + appName + ">" + appName;
                    itemDiv!.append(div);
                    this.energyTraceRow!.shadowRoot!.querySelector<HTMLDivElement>("#" + formatAppName)!.onclick = (e: any) => {
                        this.energyTraceRow?.shadowRoot!.querySelectorAll<HTMLInputElement>('input[type=radio][name=processoption]')!.forEach(item => {
                            if (item.checked) {
                                SpHiSysEventChart.app_name = item.getAttribute("value");
                            }
                        })
                        radioList = this.energyTraceRow?.shadowRoot!.querySelectorAll<HTMLInputElement>("input[type=radio][name=processoption]");
                        if (radioList != undefined) {
                            for (let index = 0; index < radioList.length; index++) {
                                if (e.path[0].id == radioList[index]!.getAttribute("app_name")) {
                                    SpHiSysEventChart.app_name = radioList[index]!.getAttribute("value");
                                    radioList[index]!.checked = true;
                                }
                            }
                        }
                        // @ts-ignore
                        appNameList!.visible = false
                        this.energyTraceRow?.click()
                    }
                }
                addFlag = true;
            }
        })
        this.energyTraceRow.rowId = `energy`
        this.energyTraceRow.rowType = TraceRow.ROW_TYPE_ENERGY
        this.energyTraceRow.rowParentId = '';
        this.energyTraceRow.folder = true;
        this.energyTraceRow.name = 'Energy';
        this.energyTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        this.energyTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        this.energyTraceRow.supplier = () => new Promise<Array<any>>((resolve) => resolve([]));
        this.energyTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `energy-Group`, {
                    list: this.energyTraceRow!.must ? this.energyTraceRow!.dataList : undefined,
                    offscreen: this.energyTraceRow!.must ? this.energyTraceRow!.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: this.energyTraceRow!.dpr,
                    isHover: this.energyTraceRow!.isHover,
                    hoverX: this.energyTraceRow!.hoverX,
                    hoverY: this.energyTraceRow!.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: this.energyTraceRow!.canvasWidth,
                    canvasHeight: this.energyTraceRow!.canvasHeight,
                    isRangeSelect: this.energyTraceRow!.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    useCache: useCache,
                    lineColor: this.energyTraceRow!.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: this.energyTraceRow!.frame,
                }, this.energyTraceRow!.must && this.energyTraceRow!.args.isOffScreen ? this.energyTraceRow!.offscreen[0] : undefined, (res: any, hover: any) => {
                    this.energyTraceRow!.must = false;
                }
            )
        }
        this.trace.rowsEL?.appendChild(this.energyTraceRow!)
    }

    private initAnomaly = async () => {
        let time = new Date().getTime()
        let anomalyTraceRow = new TraceRow<EnergyAnomalyStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        anomalyTraceRow.rowParentId = `energy`
        anomalyTraceRow.rowHidden = true
        anomalyTraceRow.rowId = "energy-anomaly"
        anomalyTraceRow.rowType = TraceRow.ROW_TYPE_ANOMALY_ENERGY
        anomalyTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        anomalyTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        anomalyTraceRow.setAttribute("height", `55px`);
        let element = anomalyTraceRow.shadowRoot?.querySelector(".root") as HTMLDivElement;
        element!.style.height = `55px`;
        anomalyTraceRow.style.width = `100%`;
        anomalyTraceRow.setAttribute('children', '');
        anomalyTraceRow.name = "Anomaly";
        anomalyTraceRow.supplier = () => queryAnomalyData()
        anomalyTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu0`, `energyAnomaly`, {
                    list: anomalyTraceRow.must ? anomalyTraceRow.dataList : undefined,
                    offscreen: anomalyTraceRow.must ? anomalyTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: anomalyTraceRow.dpr,
                    isHover: anomalyTraceRow.isHover,
                    hoverX: anomalyTraceRow.hoverX,
                    hoverY: anomalyTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: anomalyTraceRow.canvasWidth,
                    canvasHeight: anomalyTraceRow.canvasHeight,
                    hoverEnergyAnomalyStruct: EnergyAnomalyStruct.hoverEnergyAnomalyStruct,
                    selectEnergyAnomalyStruct: EnergyAnomalyStruct.selectEnergyAnomalyStruct,
                    isRangeSelect: anomalyTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    appName: SpHiSysEventChart.app_name,
                    useCache: useCache,
                    lineColor: anomalyTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: anomalyTraceRow.frame,
                }, anomalyTraceRow.must && anomalyTraceRow.args.isOffScreen ? anomalyTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    anomalyTraceRow.must = false;
                    if (anomalyTraceRow.args.isOffScreen == true) {
                        if (anomalyTraceRow.isHover) {
                            EnergyAnomalyStruct.hoverEnergyAnomalyStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_ANOMALY_ENERGY && it.name !== anomalyTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(anomalyTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the anomaly is: ', durTime)
    }

    private initSystem = async () => {
        let time = new Date().getTime()
        let systemTraceRow = new TraceRow<EnergySystemStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        systemTraceRow.rowParentId = `energy`
        systemTraceRow.rowHidden = true
        systemTraceRow.rowId = "energy-system"
        systemTraceRow.rowType = TraceRow.ROW_TYPE_SYSTEM_ENERGY
        systemTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        systemTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        systemTraceRow.setAttribute("height", `80px`);
        let element = systemTraceRow.shadowRoot?.querySelector(".root") as HTMLDivElement;
        element!.style.height = `90px`;
        systemTraceRow.style.width = `100%`;
        systemTraceRow.setAttribute('children', '');
        systemTraceRow.name = "System";
        systemTraceRow.supplier = () => querySystemData().then(result => {
            return this.getSystemData(result)
        })
        systemTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu1`, `energySystem`, {
                    list: systemTraceRow.must ? systemTraceRow.dataList : undefined,
                    offscreen: systemTraceRow.must ? systemTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: systemTraceRow.dpr,
                    isHover: systemTraceRow.isHover,
                    hoverX: systemTraceRow.hoverX,
                    hoverY: systemTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: systemTraceRow.canvasWidth,
                    canvasHeight: systemTraceRow.canvasHeight,
                    hoverEnergySystemStruct: EnergySystemStruct.hoverEnergySystemStruct,
                    selectEnergySystemStruct: EnergySystemStruct.selectEnergySystemStruct,
                    isRangeSelect: systemTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    useCache: useCache,
                    lineColor: systemTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: systemTraceRow.frame,
                }, systemTraceRow.must && systemTraceRow.args.isOffScreen ? systemTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    systemTraceRow.must = false;
                    if (systemTraceRow.args.isOffScreen == true) {
                        if (systemTraceRow.isHover) {
                            EnergySystemStruct.hoverEnergySystemStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_SYSTEM_ENERGY && it.name !== systemTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(systemTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the Ability Memory is: ', durTime)
    }

    getSystemData(result: any): Promise<any> {
        let systemDataList:any = new Array();
        let map = new Map();
        result.forEach((item: any) => {
            if (item.eventName == "WORK_ADD") {
                let systemData = this.getEnergySystemStruct(item.ts, 0);
                map.set(item.eventName, systemData);
            }
            if (item.eventName == "WORK_STOP" || item.eventName == "WORK_REMOVE") {
                let systemData = map.get("WORK_ADD");
                this.setEnergySystemStructDur(systemDataList, systemData, 0, item.ts);
                if(item.eventName == "WORK_REMOVE"){
                    map.delete("WORK_ADD")
                }
            }
            if (item.eventName == "POWER_RUNNINGLOCK" && item.Value.endsWith("ADD")) {
                let systemData = this.getEnergySystemStruct(item.ts, 1);
                map.set(item.eventName, systemData);
            }
            if (item.eventName == "POWER_RUNNINGLOCK" && item.Value.endsWith("REMOVE")) {
                let systemData = map.get("POWER_RUNNINGLOCK");
                this.setEnergySystemStructDur(systemDataList, systemData, 1, item.ts);
                map.delete("POWER_RUNNINGLOCK");
            }
            if (item.eventName == "GNSS_STATE" && item.Value.startsWith("start")) {
                let systemData = this.getEnergySystemStruct(item.ts, 2);
                map.set(item.eventName, systemData);
            }
            if (item.eventName == "GNSS_STATE" && item.Value.endsWith("stop")) {
                let systemData = map.get("GNSS_STATE");
                this.setEnergySystemStructDur(systemDataList, systemData, 2, item.ts);
                map.delete("GNSS_STATE");
            }
        })
        if (map.size > 0) {
            for (let item of map.values()) {
                systemDataList.push(item);
            }
            map.clear();
        }
        return systemDataList
    }

    private getEnergySystemStruct (startNs: number, type: number): EnergySystemStruct{
        let systemData = new EnergySystemStruct();
        systemData.startNs = startNs;
        // @ts-ignore
        systemData.dur = window.recordEndNS;
        systemData.type = type;
        return systemData;
    }

    private getEnergySystemStructDur (ts: number, type: number): EnergySystemStruct{
        let systemData = new EnergySystemStruct();
        systemData.startNs = 0;
        systemData.dur = ts - 0;
        systemData.type = type;
        return systemData;
    }

    private setEnergySystemStructDur(systemDataList: any, systemData: EnergySystemStruct, type: number, ts: number){
        if (systemData) {
            systemData.dur = ts - systemData.startNs!;
        } else {
            systemData = this.getEnergySystemStructDur(ts, type);
        }
        systemDataList.push(systemData);
    }

    private initPower = async () => {
        let time = new Date().getTime();
        let powerTraceRow = new TraceRow<EnergyPowerStruct>({
            canvasNumber: 1,
            alpha: true,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        powerTraceRow.rowParentId = `energy`
        powerTraceRow.rowHidden = true
        powerTraceRow.rowId = "energy-power"
        powerTraceRow.rowType = TraceRow.ROW_TYPE_POWER_ENERGY
        powerTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        powerTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
        powerTraceRow.setAttribute("height", `200px`);
        let element = powerTraceRow.shadowRoot?.querySelector(".root") as HTMLDivElement;
        element!.style.height = `200px`;
        powerTraceRow.style.width = `100%`;
        powerTraceRow.setAttribute('children', '');
        powerTraceRow.name = "Power"
        powerTraceRow.supplier = () => queryPowerData().then(items => {
            return this.getPowerData(items)
        })
        powerTraceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`cpu2`, `energyPower`, {
                    list: powerTraceRow.must ? powerTraceRow.dataList : undefined,
                    offscreen: powerTraceRow.must ? powerTraceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: powerTraceRow.dpr,
                    isHover: powerTraceRow.isHover,
                    hoverX: powerTraceRow.hoverX,
                    hoverY: powerTraceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: powerTraceRow.canvasWidth,
                    canvasHeight: powerTraceRow.canvasHeight,
                    hoverEnergyPowerStruct: EnergyPowerStruct.hoverEnergyPowerStruct,
                    selectEnergyPowerStruct: EnergyPowerStruct.selectEnergyPowerStruct,
                    isRangeSelect: powerTraceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxPowerName: SpHiSysEventChart.app_name,
                    useCache: useCache,
                    lineColor: powerTraceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: powerTraceRow.frame,
                }, powerTraceRow.must && powerTraceRow.args.isOffScreen ? powerTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    powerTraceRow.must = false;
                    if (powerTraceRow.args.isOffScreen == true) {
                        if (powerTraceRow.isHover) {
                            EnergyPowerStruct.hoverEnergyPowerStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_POWER_ENERGY && it.name !== powerTraceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(powerTraceRow)
        let durTime = new Date().getTime() - time;
        info('The time to load the energy power is: ', durTime)
    }

    async getPowerData(items: any): Promise<any> {
        let powerDataMap: any = {}
        let appNameList: any = []
        items.forEach((item: any) => {
            let dataItem = powerDataMap[item.startNS]
            if (dataItem == undefined) {
                if (item.appKey == "APPNAME") {
                    let appMap: any = {};
                    let appNames = item.eventValue.split(",")
                    appNameList = appNames;
                    if (appNames.length > 0) {
                        for (let appNamesKey of appNames) {
                            appMap[appNamesKey] = new EnergyPowerStruct()
                            appMap[appNamesKey].name = appNamesKey
                            appMap[appNamesKey].ts = item.startNS
                        }
                        powerDataMap[item.startNS] = appMap;
                    }
                }
            } else {
                if (item.appKey != "APPNAME") {
                    let values = item.eventValue.split(",")
                    for (let i = 0; i < values.length; i++) {
                        let appName = appNameList[i]
                        let obj = dataItem[appName]
                        if (obj != undefined) {
                            let eventName = item.eventName.split("_");
                            let s = eventName[eventName.length - 1].toLocaleLowerCase();
                            if (obj[s] == undefined) {
                                obj[s] = parseInt(values[i])
                            } else {
                                obj[s] += parseInt(values[i])
                            }
                        }
                    }
                } else {
                    let dataMap = powerDataMap[item.startNS];
                    let appNames = item.eventValue.split(",")
                    appNameList = appNames;
                    if (appNames.length > 0) {
                        for (let appNamesKey of appNames) {
                            dataMap[appNamesKey] = new EnergyPowerStruct()
                            dataMap[appNamesKey].name = appNamesKey
                            dataMap[appNamesKey].ts = item.startNS
                        }
                    }
                }
            }
        })
        return Object.values(powerDataMap)
    }


    private initState = async () => {
        let time = new Date().getTime();
        let stateList = ["Brightness nit", "Signal Level", "Wifi Event Received", "Audio Stream Change",
            "Audio Volume Change", "Wifi State", "Bluetooth Br Switch State", "Location Switch State", "Sensor State"]
        let stateName = ["BRIGHTNESS_NIT", "SIGNAL_LEVEL", "WIFI_EVENT_RECEIVED", "AUDIO_STREAM_CHANGE",
            "AUDIO_VOLUME_CHANGE", "WIFI_STATE", "BLUETOOTH_BR_SWITCH_STATE", "LOCATION_SWITCH_STATE", "SENSOR_STATE"]

        for (let index = 0; index < stateList.length; index++) {
            let maxStateData = await queryMaxStateValue(stateName[index])
            if (!maxStateData[0]) {
                continue;
            }
            let maxStateTotal = maxStateData[0].maxValue.toString()
            if (maxStateData[0].type.toLocaleLowerCase().includes("state") || maxStateData[0].type.toLocaleLowerCase().includes("sensor")) {
                if (maxStateData[0].maxValue == 0) {
                    maxStateTotal = "enable"
                } else {
                    maxStateTotal = "disable"
                }
            }
            let stateTraceRow = new TraceRow<EnergyStateStruct>({
                canvasNumber: 1,
                alpha: false,
                contextId: '2d',
                isOffScreen: SpSystemTrace.isCanvasOffScreen
            });
            stateTraceRow.rowParentId = `energy`
            stateTraceRow.rowHidden = true
            stateTraceRow.rowId = "energy-state"
            stateTraceRow.rowType = TraceRow.ROW_TYPE_STATE_ENERGY
            stateTraceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
            stateTraceRow.selectChangeHandler = this.trace.selectChangeHandler;
            stateTraceRow.style.height = '40px'
            stateTraceRow.style.width = `100%`;
            stateTraceRow.setAttribute('children', '');
            stateTraceRow.name = `${stateList[index]}`
            stateTraceRow.supplier = () => queryStateData(stateName[index])
            stateTraceRow.onThreadHandler = (useCache) => {
                procedurePool.submitWithName(`cpu${stateList.length % (index + 1)}`, `energyState${index}`, {
                        list: stateTraceRow.must ? stateTraceRow.dataList : undefined,
                        offscreen: stateTraceRow.must ? stateTraceRow.offscreen[0] : undefined,
                        xs: TraceRow.range?.xs,
                        dpr: stateTraceRow.dpr,
                        isHover: stateTraceRow.isHover,
                        hoverX: stateTraceRow.hoverX,
                        hoverY: stateTraceRow.hoverY,
                        flagMoveInfo: this.trace.hoverFlag,
                        flagSelectedInfo: this.trace.selectFlag,
                        canvasWidth: stateTraceRow.canvasWidth,
                        canvasHeight: stateTraceRow.canvasHeight,
                        hoverEnergyStateStruct: EnergyStateStruct.hoverEnergyStateStruct,
                        selectEnergyStateStruct: EnergyStateStruct.selectEnergyStateStruct,
                        isRangeSelect: stateTraceRow.rangeSelect,
                        rangeSelectObject: TraceRow.rangeSelectObject,
                        maxState: maxStateData[0].maxValue,
                        maxStateName: maxStateTotal.toString(),
                        useCache: useCache,
                        lineColor: stateTraceRow.getLineColor(),
                        startNS: TraceRow.range?.startNS || 0,
                        endNS: TraceRow.range?.endNS || 0,
                        totalNS: TraceRow.range?.totalNS || 0,
                        slicesTime: TraceRow.range?.slicesTime,
                        range: TraceRow.range,
                        frame: stateTraceRow.frame,
                    }, stateTraceRow.must && stateTraceRow.args.isOffScreen ? stateTraceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                        stateTraceRow.must = false;
                        if (stateTraceRow.args.isOffScreen == true) {
                            if (stateTraceRow.isHover) {
                                EnergyStateStruct.hoverEnergyStateStruct = hover;
                                this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_STATE_ENERGY && it.name !== stateTraceRow.name).forEach(it => it.draw(true));
                            }
                            return;
                        }
                    }
                )
            }
            this.trace.rowsEL?.appendChild(stateTraceRow)
            let durTime = new Date().getTime() - time;
            info('The time to load the Ability Memory is: ', durTime)
        }
    }

}