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
import {SpSystemTrace} from "../../../dist/trace/component/SpSystemTrace.js";
// @ts-ignore
import {TraceRow} from "../../../dist/trace/component/trace/base/TraceRow";
// @ts-ignore
import {procedurePool} from "../../../dist/trace/database/Procedure.js"

window.ResizeObserver = window.ResizeObserver ||
    jest.fn().mockImplementation(() => ({
        disconnect: jest.fn(),
        observe: jest.fn(),
        unobserve: jest.fn(),
    }));

describe('SpSystemTrace Test', ()=>{
    let spSystemTrace = new SpSystemTrace();
    const offset = 1
    const callback=true
    const rowId=""
    const rowParentId=""
    const rowType=""
    let smooth=true

    spSystemTrace.initElements = jest.fn(()=> true)


    it('SpSystemTraceTest01', function () {
        expect(spSystemTrace.getScrollWidth()).toBe(0)
    });

    it('SpSystemTraceTest02', function () {
        let resultLength = spSystemTrace.getVisibleRows([{}]).length;
        expect(resultLength).toBe(0)
    });

    it('SpSystemTraceTest03', function () {
        expect(spSystemTrace.timerShaftELRangeChange('')).toBeUndefined()
    });

    it('SpSystemTraceTest04', function () {
        expect(spSystemTrace.rowsElOnScroll('Scroll')).toBeUndefined()
    });

    it('SpSystemTraceTest05', function () {
        expect(spSystemTrace.documentOnMouseDown('MouseDown')).toBeUndefined()
    });

    it('SpSystemTraceTest06', function () {
        spSystemTrace.timerShaftEL = jest.fn(()=>null)
        spSystemTrace.timerShaftEL.sportRuler = jest.fn(()=>undefined)
        spSystemTrace.timerShaftEL.sportRuler.frame = jest.fn(()=>"")
        spSystemTrace.timerShaftEL.canvas = jest.fn(()=> undefined)
        spSystemTrace.timerShaftEL.canvas.offsetLeft = jest.fn(()=>1)
        spSystemTrace.timerShaftEL.sportRuler.frame.contains = jest.fn(()=>true)
        spSystemTrace.documentOnMouseUp = jest.fn(()=>true)
        expect(spSystemTrace.documentOnMouseUp('MouseUp')).toBeTruthy()
    });

    it('SpSystemTraceTest07', function () {
        spSystemTrace.timerShaftEL = jest.fn(()=>undefined)
        spSystemTrace.timerShaftEL.isScaling = jest.fn(()=>true)
        expect(spSystemTrace.documentOnMouseMove('MouseMove')).toBeUndefined()
    });

    it('SpSystemTraceTest08', function () {
        expect(spSystemTrace.hoverStructNull('')).toBeUndefined()
    });

    it('SpSystemTraceTest09', function () {
        expect(spSystemTrace.selectStructNull('')).toBeUndefined()
    });

    it('SpSystemTraceTest11', function () {
        expect(spSystemTrace.connectedCallback()).toBeUndefined()
    });

    it('SpSystemTraceTest12', function () {
        spSystemTrace.timerShaftEL.removeEventListener = jest.fn(()=>true)
        expect(spSystemTrace.disconnectedCallback()).toBeUndefined()
    });

    it('SpSystemTraceTest14', function () {
        expect(spSystemTrace.loadDatabaseUrl).toBeTruthy()
    });

    it('SpSystemTraceTest15', function () {
        spSystemTrace.rowsEL = jest.fn(()=>true)
        spSystemTrace.rowsEL.scrollTo = jest.fn(()=>offset)
        spSystemTrace.rowsEL.removeEventListener = jest.fn(()=>true)
        spSystemTrace.rowsEL.addEventListener = jest.fn(()=>true)
        expect(spSystemTrace.rowScrollTo(offset,callback)).toBeUndefined()
    });

    it('SpSystemTraceTest16', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        expect(spSystemTrace.onClickHandler()).toBeUndefined()
    });

    it('SpSystemTraceTest17', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        expect(spSystemTrace.search()).toBeUndefined()
    });

    it('SpSystemTraceTest18', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        expect(spSystemTrace.searchCPU()).not.toBeUndefined()
    });

    it('SpSystemTraceTest19', function () {
        expect(spSystemTrace.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: block;
            width: 100%;
            height: 100%;
        }
        .timer-shaft{
            width: 100%;
            z-index: 2;
        }
        .rows{
            color: #fff;
            display: block;
            box-sizing: border-box;
            /*flex-direction: column;*/
            /*overflow-y: auto;*/
            overflow: overlay;
            overflow-anchor: none;
            max-height: calc(100vh - 147px - 48px);
            flex: 1;
            width: 100%;
            background: var(--dark-background4,#ffffff);
            /*scroll-behavior: smooth;*/
        }
        .container{
            width: 100%;
            box-sizing: border-box;
            height: 100%;
            display: grid;
            grid-template-columns: 1fr;
            grid-template-rows: min-content min-content 1fr min-content;
        }
        .trace-sheet{
            cursor: default;
        }

        </style>
        <div class=\\"container\\">
            <timer-shaft-element class=\\"timer-shaft\\">
            </timer-shaft-element>
            <div class=\\"spacer\\"></div>
            <div class=\\"rows\\"></div>
            <trace-sheet class=\\"trace-sheet\\" mode=\\"hidden\\">
            </trace-sheet>
        </div>
        "
`);
    });

    it('SpSystemTraceTest20', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        // @ts-ignore
        TraceRow.range = jest.fn(()=>undefined)
        TraceRow.range.startNS = jest.fn(()=>1)
        spSystemTrace.onClickHandler = jest.fn(()=>true)
        expect(spSystemTrace.showPreCpuStruct(1,[{length:0}])).toBe(0)
    });

    it('SpSystemTraceTest21', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        // @ts-ignore
        TraceRow.range = jest.fn(()=>undefined)
        TraceRow.range.startNS = jest.fn(()=>1)
        spSystemTrace.onClickHandler = jest.fn(()=>true)
        expect(spSystemTrace.showNextCpuStruct(1,[{length:0}])).toBe(0)
    });

    it('SpSystemTraceTest22', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        procedurePool.clearCache = jest.fn(()=>true)
        expect(spSystemTrace.reset()).toBeUndefined()
    });
    it('SpSystemTraceTest23', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        let structs = [{
            length:1,
            starttime:1,
        }]
        let previous = 1;
        let currentIndex = 1;
        TraceRow.range = jest.fn(()=>undefined)
        TraceRow.range.startNS = jest.fn(()=>1)
        expect(spSystemTrace.showStruct(previous, currentIndex, structs)).not.toBeUndefined()
    });
    it('SpSystemTraceTest24', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        TraceRow.range = jest.fn(()=>undefined)
        TraceRow.range.startNS = jest.fn(()=>1)
        expect(spSystemTrace.closeAllExpandRows()).toBeUndefined()
    });
    it('SpSystemTraceTest25', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        spSystemTrace.rowsEL = jest.fn(()=>true)
        spSystemTrace.rowsEL.scroll = jest.fn(()=>true)
        expect(spSystemTrace.scrollToProcess()).toBeUndefined()
    });
    it('SpSystemTraceTest26', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        spSystemTrace.rowsEL = jest.fn(()=>true)
        spSystemTrace.rowsEL.scroll = jest.fn(()=>true)
        expect(spSystemTrace.scrollToDepth()).toBeUndefined()
    });
    it('SpSystemTraceTest27', function () {
        let spSystemTrace = new SpSystemTrace<any>({canvasNumber:1,alpha: true, contextId: '2d', isOffScreen: true});
        expect(spSystemTrace.searchThreadsAndProcesses()).toStrictEqual([])
    });
})
