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

import { BaseElement, element } from "../../base-ui/BaseElement.js";
import { NativeHookCallInfo } from "../bean/NativeHook.js";
import { ChartMode, ChartStruct, Rect } from "../database/ProcedureWorkerCommon.js";
import { SpApplication } from "../SpApplication.js";
import { Utils } from "./trace/base/Utils.js";

const TAG: string = "FrameChart";
const scaleHeight = 30;
const depthHeight = 20;
const filterPixiel = 2;
const sideLenght = 8;

@element('tab-framechart')
export class FrameChart extends BaseElement {
    private canvas: HTMLCanvasElement | undefined | null;
    private cavasContext: CanvasRenderingContext2D | undefined | null;
    private floatHint: HTMLDivElement | undefined | null;

    private rect: Rect = new Rect(0, 0, 0, 0);
    private _mode = ChartMode.Call;
    private startX = 0; // canvas start x coord
    private startY = 0; // canvas start y coord
    private canvasX = -1; // canvas current x
    private canvasY = -1; // canvas current y
    private hintContent = ""; // float hoint inner html content

    private historyList: Array<Array<ChartStruct>> = [];
    private currentSize = 0;
    private currentCount = 0;
    private currentData: Array<ChartStruct> = [];
    private xPoint = 0; // x in rect
    private isFocusing = false;
    private canvasScrollTop = 0;
    private _maxDepth = 0;
    private chartClickListenerList: Array<Function> = [];
    private isUpdateCanvas = false;

    static get observedAttributes() {
        return []
    }

    /**
     * set chart mode
     * @param mode chart format for data mode
     */
    set mode(mode: ChartMode) {
        this._mode = mode;
    }

    set data(val: Array<ChartStruct> | any) {
        this.historyList = [];
        ChartStruct.lastSelectFuncStruct = undefined;
        this.currentData = val;
        this.resetTrans();
        this.caldrawArgs();
        for (let callback of this.chartClickListenerList) {
            callback(true);
        }

    }

    set tabPaneScrollTop(scrollTop: number) {
        this.canvasScrollTop = scrollTop;
        this.hideFloatHint();
    }

    /**
     * add callback of chart click
     * @param callback function of chart click
     */
    public addChartClickListener(callback: Function) {
        if (this.chartClickListenerList.indexOf(callback) < 0) {
            this.chartClickListenerList.push(callback);
        }
    }

    /**
     * remove callback of chart click
     * @param callback function of chart click
     */
    public removeChartClickListener(callback: Function) {
        let index = this.chartClickListenerList.indexOf(callback);
        if (index > -1) {
            this.chartClickListenerList.splice(index, 1);
        }
    }

    /**
     * cal total count size and max Depth
     */
    private caldrawArgs(): void {
        this.currentCount = 0;
        this.currentSize = 0;
        this._maxDepth = 0;
        for (let rootNode of this.currentData!) {
            this.currentCount += rootNode.count;
            this.currentSize += rootNode.size;
            let depth = 0;
            this.calMaxDepth(rootNode, depth);
        }
        this.rect.width = this.canvas!.width
        this.rect.height = (this._maxDepth + 1) * 20 + scaleHeight; // 20px/depth and 30 is scale height
        this.canvas!.style.height = this.rect!.height + "px";
        this.canvas!.height = Math.ceil(this.rect!.height);
    }

    /**
     * cal max Depth
     * @param node every child node
     * @param depth current depth
     */
    private calMaxDepth(node: ChartStruct, depth: number): void {
        node.depth = depth;
        depth++;
        if (node.children && node.children.length > 0) {
            for (let children of node.children) {
                this.calMaxDepth(children, depth);
            }
        } else {
            this._maxDepth = Math.max(depth, this._maxDepth);
        }
    }

    /**
     * calculate Data and draw chart
     */
    async calculateChartData() {
        this.clearCanvas();
        this.cavasContext?.beginPath();
        this.drawScale();
        let x = this.xPoint;
        switch (this._mode) {
            case ChartMode.Byte:
                for (let node of this.currentData!) {
                    let width = Math.ceil(node.size / this.currentSize * this.rect!.width);
                    let height = depthHeight; // 20px / depth
                    // ensure the data for first depth frame
                    if (!node.frame) {
                        node.frame = new Rect(x, scaleHeight, width, height)
                    } else {
                        node.frame!.x = x;
                        node.frame!.y = scaleHeight;
                        node.frame!.width = width;
                        node.frame!.height = height;
                    }
                    // not draw when rect not in canvas
                    if (x + width >= 0 && x < this.canvas!.width) {
                        NativeHookCallInfo.draw(this.cavasContext!, node, node.size / this.currentSize);
                        this.drawFrameChart(node);
                    }
                    x += width;
                }
                break;
            case ChartMode.Count:
                for (let node of this.currentData!) {
                    let width = Math.ceil(node.count / this.currentCount * this.rect!.width);
                    let height = depthHeight; // 20px / depth
                    // ensure the data for first depth frame
                    if (!node.frame) {
                        node.frame = new Rect(x, scaleHeight, width, height)
                    } else {
                        node.frame!.x = x;
                        node.frame!.y = scaleHeight;
                        node.frame!.width = width;
                        node.frame!.height = height;
                    }
                    // not draw when rect not in canvas
                    if (x + width >= 0 && x < this.canvas!.width) {
                        NativeHookCallInfo.draw(this.cavasContext!, node, node.count / this.currentCount);
                    }
                    this.drawFrameChart(node);
                    x += width;
                }
                break;
        }
        this.drawTriangleOnScale();
        this.cavasContext?.closePath();
    }

    /**
     * draw last selected resct position on scale
     */
    private drawTriangleOnScale(): void {
        if (ChartStruct.lastSelectFuncStruct) {
            this.cavasContext!.fillStyle = `rgba(${82}, ${145}, ${255})`;
            let x = Math.ceil(ChartStruct.lastSelectFuncStruct.frame!.x +
                ChartStruct.lastSelectFuncStruct.frame!.width / 2)
            if (x < 0) x = sideLenght / 2;
            if (x > this.canvas!.width) x = this.canvas!.width - sideLenght;
            this.cavasContext!.moveTo(x - sideLenght / 2, scaleHeight - sideLenght);
            this.cavasContext!.lineTo(x + sideLenght / 2, scaleHeight - sideLenght);
            this.cavasContext!.lineTo(x, scaleHeight);
            this.cavasContext!.lineTo(x - sideLenght / 2, scaleHeight - sideLenght);
            this.cavasContext?.fill();
        }
    }

    /**
     * clear canvas all data
     */
    public clearCanvas(): void {
        this.cavasContext?.clearRect(0, 0, this.canvas!.width, this.canvas!.height);
    }

    /**
     * update canvas size
     */
    public updateCanvas(updateWidth: boolean, newWidth?: number): void {
        if (this.canvas instanceof HTMLCanvasElement) {
            this.canvas.style.width = 100 + "%";
            this.canvas.style.height = this.rect!.height + "px";
            if (this.canvas.clientWidth == 0 && newWidth) {
                this.canvas.width = newWidth - 40;
            } else {
                this.canvas.width = this.canvas.clientWidth;
            }
            this.canvas.height = Math.ceil(this.rect!.height);
            this.updateCanvasCoord();
        }
        if (this.rect.width == 0 || updateWidth ||
            Math.round(newWidth!) != this.canvas!.width + 40 || newWidth! > this.rect.width) {
            this.rect.width = this.canvas!.width
        }
    }

    /**
     * updateCanvasCoord
     */
    private updateCanvasCoord(): void {
        if (this.canvas instanceof HTMLCanvasElement) {
            this.isUpdateCanvas = this.canvas.clientWidth != 0;
            if (this.canvas.getBoundingClientRect()) {
                let box = this.canvas.getBoundingClientRect();
                let D = document.documentElement;
                this.startX = box.left + Math.max(D.scrollLeft, document.body.scrollLeft) - D.clientLeft;
                this.startY = box.top + Math.max(D.scrollTop, document.body.scrollTop) - D.clientTop + this.canvasScrollTop;
            }
        }
    }

    /**
     * draw top Scale Into 100 pieces
     */
    private drawScale(): void {
        let spApplication = <SpApplication>document.getElementsByTagName("sp-application")[0];
        // line
        this.cavasContext!.lineWidth = 0.5;
        this.cavasContext?.moveTo(0, 0);
        this.cavasContext?.lineTo(this.canvas!.width, 0);

        for (let i = 0; i <= 10; i++) {
            let startX = Math.floor(this.canvas!.width / 10 * i);
            for (let j = 0; j < 10; j++) {
                // children scale
                this.cavasContext!.lineWidth = 0.5;
                let startItemX = startX + Math.floor(this.canvas!.width / 100 * j);
                this.cavasContext?.moveTo(startItemX, 0);
                this.cavasContext?.lineTo(startItemX, 10);
            }
            if (i == 0) continue; // skip first Size is 0
            // long line every 10 count
            this.cavasContext!.lineWidth = 1;
            let sizeRatio = this.canvas!.width / this.rect.width; // scale ratio
            if (spApplication.dark) {
                this.cavasContext!.strokeStyle = "#888";
            } else {
                this.cavasContext!.strokeStyle = "#ddd";
            }
            this.cavasContext?.moveTo(startX, 0);
            this.cavasContext?.lineTo(startX, this.canvas!.height);
            if (spApplication.dark) {
                this.cavasContext!.fillStyle = "#fff";
            } else {
                this.cavasContext!.fillStyle = "#000";
            }
            let scale = '';
            if (this._mode == ChartMode.Byte) {
                scale = Utils.getByteWithUnit(this.currentSize * sizeRatio / 10 * i);
            } else {
                scale = (this.currentCount * sizeRatio / 10 * i).toFixed(0) + '';
            }
            this.cavasContext?.fillText(scale, startX + 5, depthHeight, 50); // 50 is Text max Lenght
            this.cavasContext?.stroke();
        }
    }

    /**
     * draw chart
     * @param node draw chart by every piece
     */
    drawFrameChart(node: ChartStruct) {
        if (node.children && node.children.length > 0) {
            for (let children of node.children) {
                children.parent = node;
                let percent = 0;
                if (this._mode == ChartMode.Byte) {
                    NativeHookCallInfo.setFuncFrame(children, this.rect, this.currentSize, this._mode);
                    percent = children.size / this.currentSize;
                } else {
                    NativeHookCallInfo.setFuncFrame(children, this.rect, this.currentCount, this._mode);
                    percent = children.count / this.currentCount;
                }
                // not draw when rect not in canvas
                if ((children.frame!.x + children.frame!.width >= 0 &&
                    children.frame!.x < this.canvas!.width && children.frame!.width > filterPixiel) || children.needShow) {
                    NativeHookCallInfo.draw(this.cavasContext!, children, percent);
                }
                this.drawFrameChart(children);
            }
        }
    }

    /**
     * find target node from tree by mouse position
     *
     * @param nodes tree nodes
     * @param canvasX x coord of canvas
     * @param canvasY y coord of canvas
     * @returns target node
     */
    private searchData(nodes: Array<ChartStruct>, canvasX: number, canvasY: number): any {
        for (let node of nodes) {
            if (node.frame?.contains(canvasX, canvasY)) {
                return node;
            } else {
                let result = this.searchData(node.children, canvasX, canvasY);
                if (!result) continue; // if not found in this branch;search another branch
                return result;
            }
        }
        return null;
    }

    /**
     * show float hint and update position
     */
    private updateFloatHint(): void {
        this.floatHint!.innerHTML = this.hintContent;
        this.floatHint!.style.display = 'flex';
        let x = this.canvasX;
        let y = this.canvasY - this.canvasScrollTop;
        //right rect hint show left
        if (this.canvasX + this.floatHint!.clientWidth > (this.canvas?.clientWidth || 0)) {
            x -= this.floatHint!.clientWidth - 1;
        } else {
            x += scaleHeight;
        }
        //bottom rect hint show top
        y -= this.floatHint!.clientHeight - 1;

        this.floatHint!.style.transform = `translate(${x}px,${y}px)`;
    }

    /**
     * redraw Chart while click to scale chart
     * @param selectData select Rect data as array
     */
    private redrawChart(selectData: Array<ChartStruct>): void {
        this.currentData = selectData;
        if (selectData.length == 0) return;
        this.caldrawArgs();
        this.calculateChartData();
    }

    /**
     * press w to zoom in, s to zoom out
     * @param index < 0 zoom out , > 0 zoom in
     */
    private scale(index: number): void {
        let newWidth = 0;
        // zoom in
        let deltaWidth = this.rect!.width * 0.2;
        if (index > 0) {
            newWidth = this.rect!.width + deltaWidth;
            // max scale
            let sizeRatio = this.canvas!.width / this.rect.width;
            if (this._mode == ChartMode.Byte) {
                if (Math.round(this.currentSize * sizeRatio) <= 10) {
                    newWidth = this.canvas!.width / (10 / this.currentSize);
                }
            } else {
                if (Math.round(this.currentCount * sizeRatio) <= 10) {
                    if (this.xPoint == 0) {
                        return;
                    }
                    newWidth = this.canvas!.width / (10 / this.currentCount);
                }
            }
            deltaWidth = newWidth - this.rect!.width;
        } else { // zoom out
            newWidth = this.rect!.width - deltaWidth;
            // min scale
            if (newWidth < this.canvas!.width) {
                newWidth = this.canvas!.width;
                this.resetTrans();
            }
            deltaWidth = this.rect!.width - newWidth;
        }
        // width not change
        if (newWidth == this.rect.width) return;
        this.translationByScale(index, deltaWidth, newWidth);
    }

    private resetTrans() {
        this.xPoint = 0;
    }

    /**
     * translation after scale
     * @param index is zoom in
     * @param deltaWidth scale delta width
     * @param newWidth rect width after scale
     */
    private translationByScale(index: number, deltaWidth: number, newWidth: number): void {
        let translationValue = deltaWidth * (this.canvasX - this.xPoint) / this.rect.width;
        if (index > 0) {
            this.xPoint -= translationValue;
        } else {
            this.xPoint += translationValue;
        }
        this.rect!.width = newWidth;
        this.translationDraw();
    }

    /**
     * press a/d to translate rect
     * @param index left or right
     */
    private translation(index: number): void {
        let offset = this.canvas!.width / 10;
        if (index < 0) {
            this.xPoint += offset;
        } else {
            this.xPoint -= offset;
        }
        this.translationDraw();
    }

    /**
     * judge position ro fit canvas and draw
     */
    private translationDraw(): void {
        // rightad trans limit
        if (this.xPoint > 0) {
            this.xPoint = 0;
        }
        // left trans limit
        if (this.rect.width + this.xPoint < this.canvas!.width) {
            this.xPoint = this.canvas!.width - this.rect.width;
        }
        this.calculateChartData();
    }

    /**
     * canvas click
     * @param e MouseEvent
     */
    private onMouseClick(e: MouseEvent): void {
        if (e.button == 0) { // mouse left button
            if (ChartStruct.hoverFuncStruct && ChartStruct.hoverFuncStruct != ChartStruct.selectFuncStruct) {
                this.drawDataSet(ChartStruct.lastSelectFuncStruct!, false);
                ChartStruct.lastSelectFuncStruct = undefined;
                ChartStruct.selectFuncStruct = ChartStruct.hoverFuncStruct;
                this.historyList.push(this.currentData!);
                let selectData = new Array<ChartStruct>();
                selectData.push(ChartStruct.selectFuncStruct!);
                // reset scale and translation
                this.rect.width = this.canvas!.clientWidth;
                this.resetTrans();
                this.redrawChart(selectData);
                for (let callback of this.chartClickListenerList) {
                    callback(false);
                }
            }
        } else if (e.button == 2) { // mouse right button
            ChartStruct.selectFuncStruct = undefined;
            if (this.currentData.length == 1 && this.historyList.length > 0) {
                ChartStruct.lastSelectFuncStruct = this.currentData[0];
                this.drawDataSet(ChartStruct.lastSelectFuncStruct, true);
            }
            if (this.historyList.length > 0) {
                // reset scale and translation
                this.rect.width = this.canvas!.clientWidth;
                this.resetTrans();
                this.redrawChart(this.historyList.pop()!);
            }
            if (this.historyList.length === 0) {
                for (let callback of this.chartClickListenerList) {
                    callback(true);
                }
            }
        }
        this.hideFloatHint();
    }

    private hideFloatHint(){
        if (this.floatHint) {
            this.floatHint.style.display = 'none';
        }
    }

    /**
     * set current select rect parents will show
     * @param data current noode
     * @param isShow is show in chart
     */
    private drawDataSet(data: ChartStruct, isShow: boolean): void {
        if (data) {
            data.needShow = isShow;
            if (data.parent) {
                this.drawDataSet(data.parent, isShow);
            }
        }
    }

    /**
     * mouse on canvas move event
     */
    private onMouseMove(): void {
        let lastNode = ChartStruct.hoverFuncStruct;
        let searchResult = this.searchData(this.currentData!, this.canvasX, this.canvasY);
        if (searchResult && (searchResult.frame!.width > filterPixiel ||
            searchResult.needShow || searchResult.depth == 0)) {
            ChartStruct.hoverFuncStruct = searchResult;
            // judge current node is hover redraw chart
            if (searchResult != lastNode) {
                let name = ChartStruct.hoverFuncStruct?.symbol;
                if (this._mode == ChartMode.Byte) {
                    let size = Utils.getByteWithUnit(ChartStruct.hoverFuncStruct!.size);
                    this.hintContent = `<span>Name: ${name} </span><span>Size: ${size}</span>`;
                } else {
                    let count = ChartStruct.hoverFuncStruct!.count;
                    this.hintContent = `<span>Name: ${name} </span><span>Count: ${count}</span>`;
                }
                this.calculateChartData();
            }
            // pervent float hint trigger onmousemove event
            this.updateFloatHint();
        } else {
            this.hideFloatHint();
            ChartStruct.hoverFuncStruct = undefined;
        }
    }

    initElements(): void {
        this.canvas = this.shadowRoot?.querySelector("#canvas");
        this.cavasContext = this.canvas?.getContext("2d");
        this.floatHint = this.shadowRoot?.querySelector('#float_hint');

        this.canvas!.oncontextmenu = () => {
            return false;
        };
        this.canvas!.onmouseup = (e) => {
            this.onMouseClick(e);
        }

        this.canvas!.onmousemove = (e) => {
            if (!this.isUpdateCanvas) {
                this.updateCanvasCoord();
            }
            this.canvasX = e.clientX - this.startX;
            this.canvasY = e.clientY - this.startY + this.canvasScrollTop;
            this.isFocusing = true;
            this.onMouseMove();
        };

        this.canvas!.onmouseleave = () => {
            ChartStruct.selectFuncStruct = undefined;
            this.isFocusing = false;
            this.hideFloatHint();
        };

        document.addEventListener('keydown', (e) => {
            if (!this.isFocusing) return;
            switch (e.key.toLocaleLowerCase()) {
                case 'w':
                    this.scale(1);
                    break;
                case 's':
                    this.scale(-1);
                    break;
                case 'a':
                    this.translation(-1);
                    break;
                case 'd':
                    this.translation(1);
                    break;
            }
        });
        new ResizeObserver((entries) => {
            if (this.canvas!.getBoundingClientRect()) {
                let box = this.canvas!.getBoundingClientRect();
                let D = document.documentElement;
                this.startX = box.left + Math.max(D.scrollLeft, document.body.scrollLeft) - D.clientLeft;
                this.startY = box.top + Math.max(D.scrollTop, document.body.scrollTop) - D.clientTop + this.canvasScrollTop;
            }
        }).observe(document.documentElement);
    }

    initHtml(): string {
        return `
            <style>
            :host{
                display: flex;
                padding: 10px 10px;
            }
            .tip{
                position:absolute;
                left: 0;
                background-color: white;
                border: 1px solid #f9f9f9;
                width: auto;
                font-size: 8px;
                color: #50809e;
                flex-direction: column;
                justify-content: center;
                align-items: flex-start;
                padding: 2px 10px;
                display: none;
                user-select: none;
            }
            </style>
            <canvas id="canvas"></canvas>
            <div id ="float_hint" class="tip"></div>`;
    }
}