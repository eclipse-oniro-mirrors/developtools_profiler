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
// @ts-ignore
import {
    ChartStruct,
    drawFlagLine,
    drawLines,
    getFrameChartColor,
    getHeatColor,
    Point,
    Rect,
    ns2s,
    ns2x,
    drawSelection,
    drawWakeUp
    // @ts-ignore
} from "../../../../dist/trace/database/ui-worker/ProcedureWorkerCommon.js"
// @ts-ignore
import {Flag} from "../../../../dist/trace/database/ui-worker/ProcedureWorkerTimeline.js";
// @ts-ignore
import {ColorUtils} from "../../../../dist/trace/component/trace/base/ColorUtils.js";

describe('ProcedureWorkerCommon Test', () => {
    let rect = new Rect();


    it('ProcedureWorkerCommon01', function () {
        expect(rect.contains(1, 2)).not.toBeUndefined();
    });

    it('ProcedureWorkerCommon02', function () {
        expect(rect.containsWithPadding()).not.toBeUndefined();
    });

    it('ProcedureWorkerCommon03', function () {
        let point = new Point();
        expect(point).not.toBeUndefined();
    })


    it('ProcedureWorkerCommon04', function () {
        let rect = new Rect();
        expect(Rect.contains(rect, 1, 2)).toBe(false);
    })


    it('ProcedureWorkerCommon05', function () {
        let rect = new Rect();
        expect(Rect.containsWithPadding(rect, 1, 2, 1, 2)).toBe(false);
    })

    it('ProcedureWorkerCommon06', function () {
        let rect = new Rect();
        expect(Rect.containsWithMargin(rect, 1, 2, 1, 2, 1, 1)).toBe(false);
    })


    it('ProcedureWorkerCommon07', function () {
        let rect = new Rect();
        let rect2 = new Rect();
        expect(Rect.intersect(rect, rect2)).toBe(false);
    })

    it('ProcedureWorkerCommon08', function () {
        let rect = new Rect();
        expect(rect.containsWithMargin(1, 2, 3, 5, 4, 5)).toBe(false);
    })

    it('ProcedureWorkerCommon09', function () {
        let rect = new Rect();
        expect(rect.containsWithPadding(1, 2, 3, 5)).toBe(false);
    })

    it('ProcedureWorkerCommon10', function () {
        let rect = new Rect();
        let rect2 = new Rect();
        expect(rect.intersect(rect2)).toBe(false);
    })


    it('ProcedureWorkerCommon011', function () {
        expect(ColorUtils.formatNumberComma("11232")).toBe("11,232");
    })

    it('ProcedureWorkerCommon012', function () {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        let aaa = [1, 2, 3]
        drawLines(ctx, aaa, 1, "#ffff")
        expect(ColorUtils.formatNumberComma("11232")).toBe("11,232");
    })

    it('ProcedureWorkerCommon013', function () {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        let aaa = [1, 2, 3]
        let flag = new Flag(1, 2, 3, 4, 5, "#FFF", false);
        let rect2 = new Rect();
        drawFlagLine(ctx, aaa, flag, 1, 2, 2, rect2)
        expect(ColorUtils.formatNumberComma("11232")).toBe("11,232");
    })


    it('ProcedureWorkerCommon20', function () {
        expect(ns2s(2_000_000_000)).toBe("2.0 s");
    });

    it('ProcedureWorkerCommon21', function () {
        expect(ns2s(2_000_000)).toBe("2.0 ms");
    });

    it('ProcedureWorkerCommon22', function () {
        expect(ns2s(2_000)).toBe("2.0 μs");
    });

    it('ProcedureWorkerCommon23', function () {
        expect(ns2s(1)).toBe("1.0 ns");
    });

    it('ProcedureWorkerCommon24', function () {
        expect(ns2s(-1)).toBe("-1.0 s");
    });

    it('ProcedureWorkerCommon25', function () {
        expect(ColorUtils.hashFunc("",10,10)).toBe(3);
    });

    it('ProcedureWorkerCommon26', function () {
        expect(ns2x(10,1,0,1,{width:2})).toBe(2);
    });

    it('ProcedureWorkerCommon27', function () {
        expect(ns2x(-10,1,0,1,{width:2})).toBe(0);
    });

    it('ProcedureWorkerCommon28', function () {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        let flag = {
            color:"",
            x:1
        }
        let select ={
            color:"",
            x:1,
            time:"",
        }
        let frame ={
            height:1
        }
        let slicesTime ={
            startTime:1,
            endTime:1,
            color:"#dadada"
        }
        expect(drawFlagLine(ctx,flag,select,1,2,1,frame,slicesTime)).toBeUndefined();
    });

    it('ProcedureWorkerCommon29', function () {
        let context = {
            globalAlpha:0.5,
            fillStyle:"#666666",
        }
        let params = {
            isRangeSelect:'',
            rangeSelectObject: {
                startX:1,
                endX:10,
                startNS:1,
                endNS:10,
            },
            startNS:1,
            endNS:10,
            totalNS:9,
            frame:{
                y:0,
            },

        }
        expect(drawSelection(context,params)).toBeUndefined();
    });

    it('ProcedureWorkerCommon30', function () {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const context = canvas.getContext('2d');
        let wake = {
            wakeupTime:2,
            cpu:1
        }
        let frame = new Rect(0, 10, 10, 10);
        expect(drawWakeUp(context,wake,1,2,1,frame,undefined,undefined)).toBeUndefined();
    });
})

