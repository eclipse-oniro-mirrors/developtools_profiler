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
    ColorUtils,
    drawFlagLine,
    drawLines,
    getFrameChartColor,
    getHeatColor,
    Point,
    Rect,
    ns2s
    // @ts-ignore
} from "../../../dist/trace/database/ProcedureWorkerCommon.js"
// @ts-ignore
import {Flag} from "../../../dist/trace/database/ProcedureWorkerTimeline.js";

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


    it('ProcedureWorkerCommon014', function () {
        expect(getHeatColor(1).b).toBe(100);
    })

    it('ProcedureWorkerCommon015', function () {
        expect(getFrameChartColor(1,"").b).toBe(100);
    })

    it('ProcedureWorkerCommon016', function () {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        const Sourcedata = {
            frame: {
                x: 20,
                y: 20,
                width: 100,
                height: 100
            },
            percent: 200,
            value: 50
        };
        // @ts-ignore
        document.body.innerHTML = `<sp-application> </sp-application>`;
        expect(ChartStruct.draw(ctx,Sourcedata,1)).toBeUndefined()
    })

    it('ProcedureWorkerCommon017', function () {
        const canvas = document.createElement('canvas');
        canvas.width = 1;
        canvas.height = 1;
        const ctx = canvas.getContext('2d');
        let rect2 = new Rect();
        let rect = new Rect();
        expect(ChartStruct.drawString(ctx,"111",1,rect)).toBe(false);
    })

    it('ProcedureWorkerCommon018', function () {

        expect(ChartStruct.isHover()).toBeTruthy()
    })

    it('ProcedureWorkerCommon019 ', function () {
        const node = {
            frame: {
                x: 20,
                y: 20,
                width: 100,
                height: 100,
            },
            total: 50,
            size: 50,
            count: 50,
            parent: {
                children:[{
                    frame: {
                        x: 20,
                        y: 20,
                        width: 100,
                        height: 100,
                    },
                }],
                frame: {
                    x: 20,
                    y: 20,
                    width: 100,
                    height: 100,
                },
            }

        }
        let frame = new Rect(0, 10, 10, 10);
        expect(ChartStruct.setFuncFrame(node,frame,1,)).toBeUndefined()
    });

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
})

