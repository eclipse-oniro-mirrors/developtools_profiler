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
import {getFps} from "../../database/SqlLite.js";
import {TraceRow} from "../trace/base/TraceRow.js";
import {FpsStruct} from "../../bean/FpsStruct.js";
import {procedurePool} from "../../database/Procedure.js";
import {CpuStruct} from "../../bean/CpuStruct.js";
import {info} from "../../../log/Log.js";

export class SpFpsChart {
    private trace: SpSystemTrace;

    constructor(trace: SpSystemTrace) {
        this.trace = trace;
    }

    async init() {
        let res = await getFps();
        if (res.length == 0) {
            return;
        }
        let startTime = new Date().getTime();
        let fpsRow = new TraceRow<FpsStruct>({canvasNumber: 1, alpha: true, contextId: '2d', isOffScreen: true});
        fpsRow.rowId = `fps`
        fpsRow.rowType = TraceRow.ROW_TYPE_FPS
        fpsRow.rowParentId = ''
        FpsStruct.maxFps = 0
        fpsRow.style.height = '40px'
        fpsRow.name = "FPS"
        fpsRow.supplier = () => new Promise<Array<any>>((resolve, reject) => resolve(res));
        fpsRow.favoriteChangeHandler = this.trace.favoriteChangeHandler;
        fpsRow.selectChangeHandler = this.trace.selectChangeHandler;
        fpsRow.onThreadHandler = (useCache) => {
            procedurePool.submitWithName(`process0`, `fps0`, {
                list: fpsRow.must ? fpsRow.dataList : undefined,
                offscreen: !fpsRow.isTransferCanvas ? fpsRow.offscreen[0] : undefined,
                xs: TraceRow.range?.xs,
                dpr: fpsRow.dpr,
                isHover: fpsRow.isHover,
                flagMoveInfo: this.trace.hoverFlag,
                flagSelectedInfo: this.trace.selectFlag,
                hoverX: fpsRow.hoverX,
                hoverY: fpsRow.hoverY,
                hoverFpsStruct: FpsStruct.hoverFpsStruct,
                canvasWidth: fpsRow.canvasWidth,
                canvasHeight: fpsRow.canvasHeight,
                wakeupBean: CpuStruct.wakeupBean,
                isRangeSelect: fpsRow.rangeSelect,
                rangeSelectObject: TraceRow.rangeSelectObject,
                useCache: useCache,
                lineColor: fpsRow.getLineColor(),
                startNS: TraceRow.range?.startNS || 0,
                endNS: TraceRow.range?.endNS || 0,
                totalNS: TraceRow.range?.totalNS || 0,
                slicesTime: TraceRow.range?.slicesTime,
                range: TraceRow.range,
                frame: fpsRow.frame
            }, !fpsRow.isTransferCanvas ? fpsRow.offscreen[0] : undefined, (res: any, hover: any) => {
                fpsRow.must = false;
                if (fpsRow.args.isOffScreen == true) {
                    if (fpsRow.isHover) {
                        FpsStruct.hoverFpsStruct = hover;
                        this.trace.visibleRows.filter(it => it.rowType === TraceRow.ROW_TYPE_FPS && it.name !== fpsRow.name).forEach(it => it.draw(true));
                    }
                    return;
                }
            });
            fpsRow.isTransferCanvas = true;
        }
        this.trace.rowsEL?.appendChild(fpsRow)
        let durTime = new Date().getTime() - startTime;
        info('The time to load the FPS data is: ', durTime)
    }
}