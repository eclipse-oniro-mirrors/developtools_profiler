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
import {TraceRow} from "../trace/base/TraceRow.js";
import {CounterStruct, SdkSliceStruct} from "../../bean/SdkStruct.js";
import {procedurePool} from "../../database/Procedure.js";
import {BaseStruct} from "../../bean/BaseStruct.js";
import {
    queryCounterMax,
    querySdkCount,
    querySdkCounterData,
    querySdkSliceData,
    queryStartTime,
} from "../../database/SqlLite.js";

export class SpSdkChart {
    private trace: SpSystemTrace;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    parseJson(startTime: number, map: Map<number, string>) {
        let tablesMap = new Map();
        let keys = map.keys();
        for (let key of keys) {
            let table = []
            let configStr = map.get(key);
            if (configStr != undefined) {
                let json = JSON.parse(configStr);
                let tableConfig = json.tableConfig
                let setting = json.settingConfig
                if (tableConfig != null) {
                    let showTypes = tableConfig.showType;
                    for (let i = 0; i < showTypes.length; i++) {
                        let showType = showTypes[i];
                        let type = this.getTableType(showType);
                        if (type == "counter") {
                            let chartSql = this.createSql(startTime, showType.tableName, showType.columns, "where counter_id" +
                                " = $counter_id");
                            let maxValue = this.createMaxValueSql(showType.tableName, "where counter_id = $counter_id");
                            let innerTable = showType.inner;
                            let countSql = this.createSql(startTime, innerTable.tableName, innerTable.columns);
                            table.push({
                                countSql: countSql,
                                chartSql: chartSql,
                                maxSql: maxValue,
                                type: "counter",
                                name: setting.name
                            })
                        } else if (type == "slice") {
                            let chartSql = this.createSliceSql(startTime, showType.tableName, showType.columns, "where" +
                                " slice_id = $column_id and (start_ts - " + startTime + ") between $startNS and $endNS;");
                            let innerTable = showType.inner;
                            let countSql = this.createSql(startTime, innerTable.tableName, innerTable.columns);
                            table.push({countSql: countSql, chartSql: chartSql, type: "slice", name: setting.name})
                        }
                    }
                    tablesMap.set(key, table);
                }
            }
        }
        return tablesMap;
    }

    private getTableType(showType: any) {
        let columns = showType.columns;
        for (let i = 0; i < columns.length; i++) {
            let column = columns[i];
            let showType = column.showType
            if (showType != null) {
                if (showType.indexOf(1) != -1) {
                    return "counter"
                }
                if (showType.indexOf(2) != -1) {
                    return "slice"
                }
            }
        }
        return ""
    }

    private createSliceSql(startTime: number, tableName: string, columns: Array<any>, where?: string): string {
        let selectSql = "select "
        for (let i = 0; i < columns.length; i++) {
            let column = columns[i];
            if (column.column == "start_ts") {
                column.column = "(start_ts - " + startTime + ") AS start_ts"
            }
            if (column.column == "end_ts") {
                column.column = "(end_ts - " + startTime + ") AS end_ts"
            }
            if (i == (columns.length - 1)) {
                selectSql = selectSql + column.column + " "
            } else {
                selectSql = selectSql + column.column + ", "
            }
        }
        selectSql = selectSql + "from " + tableName
        if (where != undefined) {
            selectSql = selectSql + " " + where
        }
        return selectSql;
    }

    private createMaxValueSql(tableName: string, where?: string): string {
        let selectSql = "select max(value) as max_value from " + tableName
        if (where != undefined) {
            selectSql = selectSql + " " + where
        }
        return selectSql;
    }

    private createSql(startTime: number, tableName: string, columns: Array<any>, where?: string): string {
        let selectSql = "select "
        for (let i = 0; i < columns.length; i++) {
            let column = columns[i];
            if (column.column == "ts") {
                column.column = "ts - " + startTime + " AS ts"
            }
            if (i == (columns.length - 1)) {
                selectSql = selectSql + column.column + " "
            } else {
                selectSql = selectSql + column.column + ", "
            }
        }
        selectSql = selectSql + "from " + tableName
        if (where != undefined) {
            selectSql = selectSql + " " + where
        }
        return selectSql;
    }

    async init() {
        let configMap = SpSystemTrace.SDK_CONFIG_MAP
        if (configMap == undefined) return;
        let res = await queryStartTime();
        let startTime = res[0].start_ts;
        let tablesMap = this.parseJson(startTime, configMap)
        let tableKeys = tablesMap.keys();
        for (let componentId of tableKeys) {
            let table = tablesMap.get(componentId);
            if (table != null) {
                let nodeRow = this.initNodeRow(componentId, table[0].name);
                for (let index = 0; index < table.length; index++) {
                    let sqlMap = table[index]
                    if (sqlMap.type == "counter") {
                        let result = await querySdkCount(sqlMap.countSql, componentId);
                        for (let i = 0; i < result.length; i++) {
                            await this.initCounter(nodeRow, i, result[i], sqlMap, componentId);
                        }
                    } else if (sqlMap.type == "slice") {
                        let result = await querySdkCount(sqlMap.countSql, componentId);
                        for (let i = 0; i < result.length; i++) {
                            await this.initSlice(nodeRow, i, result[i], sqlMap, componentId);
                        }
                    }
                }
            }
        }
    }

    private initNodeRow = (index: number, name: string) => {
        let traceRow = new TraceRow<BaseStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        traceRow.rowId = `Sdk-${index}`
        traceRow.rowParentId = '';
        traceRow.folder = true;
        traceRow.name = `Sdk ${name}`;
        traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        traceRow.selectChangeHandler = this.trace.selectChangeHandler;
        traceRow.supplier = () => new Promise<Array<any>>((resolve) => resolve([]));
        traceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process0`, `nodeGroup`, {
                    list: traceRow.must ? traceRow.dataList : undefined,
                    offscreen: traceRow.must ? traceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: traceRow.dpr,
                    isHover: traceRow.isHover,
                    hoverX: traceRow.hoverX,
                    hoverY: traceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: traceRow.canvasWidth,
                    canvasHeight: traceRow.canvasHeight,
                    isRangeSelect: traceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    useCache: useCache,
                    lineColor: traceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: traceRow.frame,
                }, traceRow.must && traceRow.args.isOffScreen ? traceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    traceRow.must = false;
                }
            )
        }
        this.trace.rowsEL?.appendChild(traceRow)
        return traceRow;
    }

    private initCounter = async (nodeRow: TraceRow<BaseStruct>, index: number, result: any, sqlMap: any, componentId: number) => {
        let traceRow = new TraceRow<CounterStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        traceRow.rowParentId = `Sdk-${componentId}`
        traceRow.rowHidden = !nodeRow.expansion
        traceRow.rowId = result.counter_id + "-" + componentId
        traceRow.rowType = TraceRow.ROW_TYPE_SDK_COUNTER
        traceRow.folderPaddingLeft = 30;
        traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        traceRow.selectChangeHandler = this.trace.selectChangeHandler;
        traceRow.style.height = '40px'
        traceRow.style.width = `100%`;
        traceRow.setAttribute('children', '');
        traceRow.name = `${result.counter_name}`;
        traceRow.supplier = () => querySdkCounterData(sqlMap.chartSql, result.counter_id, componentId)
        let maxList = await queryCounterMax(sqlMap.maxSql, result.counter_id, componentId);
        let maxCounter = maxList[0].max_value;
        traceRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process${index % 8}`, `sdkCounter${index}`, {
                    list: traceRow.must ? traceRow.dataList : undefined,
                    offscreen: traceRow.must ? traceRow.offscreen[0] : undefined,
                    xs: TraceRow.range?.xs,
                    dpr: traceRow.dpr,
                    isHover: traceRow.isHover,
                    hoverX: traceRow.hoverX,
                    hoverY: traceRow.hoverY,
                    flagMoveInfo: this.trace.hoverFlag,
                    flagSelectedInfo: this.trace.selectFlag,
                    canvasWidth: traceRow.canvasWidth,
                    canvasHeight: traceRow.canvasHeight,
                    hoverCounterStruct: CounterStruct.hoverCounterStruct,
                    selectCounterStruct: CounterStruct.selectCounterStruct,
                    isRangeSelect: traceRow.rangeSelect,
                    rangeSelectObject: TraceRow.rangeSelectObject,
                    maxCounter: maxCounter + "",
                    maxCounterName: maxCounter + "",
                    useCache: useCache,
                    lineColor: traceRow.getLineColor(),
                    startNS: TraceRow.range?.startNS || 0,
                    endNS: TraceRow.range?.endNS || 0,
                    totalNS: TraceRow.range?.totalNS || 0,
                    slicesTime: TraceRow.range?.slicesTime,
                    range: TraceRow.range,
                    frame: traceRow.frame,
                }, traceRow.must && traceRow.args.isOffScreen ? traceRow.offscreen[0] : undefined, (res: any, hover: any) => {
                    traceRow.must = false;
                    if (traceRow.args.isOffScreen == true) {
                        if (traceRow.isHover) {
                            CounterStruct.hoverCounterStruct = hover;
                            this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_SDK_COUNTER && it.name !== traceRow.name).forEach(it => it.draw(true));
                        }
                        return;
                    }
                }
            )
        }
        this.trace.rowsEL?.appendChild(traceRow)
    }

    private initSlice = async (nodeRow: TraceRow<BaseStruct>, index: number, result: any, sqlMap: any, componentId: number) => {
        let traceRow = new TraceRow<SdkSliceStruct>({
            canvasNumber: 1,
            alpha: false,
            contextId: '2d',
            isOffScreen: SpSystemTrace.isCanvasOffScreen
        });
        traceRow.rowType = TraceRow.ROW_TYPE_SDK_SLICE
        traceRow.rowHidden = !nodeRow.expansion
        traceRow.rowParentId = `Sdk-${componentId}`
        traceRow.folderPaddingLeft = 30;
        traceRow.style.height = '40px'
        traceRow.style.width = `100%`;
        traceRow.name = `${result.slice_name}`
        traceRow.setAttribute('children', '');
        traceRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        traceRow.selectChangeHandler = this.trace.selectChangeHandler;
        traceRow.rowId = result.slice_id + "-" + componentId
        traceRow.supplier = () => querySdkSliceData(sqlMap.chartSql, result.slice_id, TraceRow.range?.startNS || 0, TraceRow.range?.endNS || 0, componentId)
        traceRow.onThreadHandler = ((useCache: boolean, buf: ArrayBuffer | undefined | null) => {
            procedurePool.submitWithName(`process${index % 8}`, `sdkSlice${index}`, {
                list: traceRow.must ? traceRow.dataList : undefined,
                offscreen: !traceRow.isTransferCanvas ? traceRow.offscreen[0] : undefined,//是否离屏
                dpr: traceRow.dpr,//屏幕dpr值
                xs: TraceRow.range?.xs,//线条坐标信息
                isHover: traceRow.isHover,
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                hoverX: traceRow.hoverX,
                hoverY: traceRow.hoverY,
                canvasWidth: traceRow.canvasWidth,
                canvasHeight: traceRow.canvasHeight,
                hoverSdkSliceStruct: SdkSliceStruct.hoverSdkSliceStruct,
                selectSdkSliceStruct: SdkSliceStruct.selectSdkSliceStruct,
                isRangeSelect: traceRow.rangeSelect,
                rangeSelectObject: TraceRow.rangeSelectObject,
                useCache: useCache,
                lineColor: traceRow.getLineColor(),
                startNS: TraceRow.range?.startNS || 0,
                endNS: TraceRow.range?.endNS || 0,
                totalNS: TraceRow.range?.totalNS || 0,
                slicesTime: TraceRow.range?.slicesTime,
                range: TraceRow.range,
                frame: traceRow.frame
            }, traceRow.getTransferArray(), (res: any, hover: any) => {
                traceRow.must = false;
                if (traceRow.isHover) {
                    SdkSliceStruct.hoverSdkSliceStruct = hover;
                    if (TraceRow.range) TraceRow.range.refresh = false;
                    this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_SDK_SLICE && it.name !== traceRow.name).forEach(it => it.draw(true));
                }
            })
            traceRow.isTransferCanvas = true;
        })
        this.trace.rowsEL?.appendChild(traceRow)
    }

}