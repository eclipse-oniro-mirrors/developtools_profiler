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

@element('tab-native-data-modal')
export class DisassemblingWindow extends BaseElement {
    private canvas: HTMLCanvasElement | undefined | null;
    private window: HTMLElement | undefined | null;
    private loading: HTMLElement | undefined | null;
    private ctx: CanvasRenderingContext2D | null | undefined;
    private hintLine = 0;
    private addrArray = new Array<string>();
    private maxBinSize = 0;
    private close: Function | undefined | null;
    setCloseListener(callback:Function){
        this.close = callback;
    }

    removeCloseListener(){
        this.close = null;
    };

    private getMap(content: string, hintAttr: string) {
        let lines = content.split('\n');
        this.addrArray = new Array<string>();
        let lineMap = new Map<string, Disassembling>();
        let effectLint = 0;
        this.maxBinSize = 0;
        for (let line of lines) {
            let lineContents = line.split(':');
            if (lineContents.length === 2) {
                let addrHex = lineContents[0].trim();
                let addr = '0x' + addrHex;
                let value = lineContents[1].split('\t');
                try {
                    let binary = value[0];
                    let lineStruct = new Disassembling();
                    if (binary === '') {
                        if (line.includes('Disassembly') || line.includes('file format')) {
                            continue
                        } else {
                            if (addr.includes(' ')) {
                                let funcs = addr.split(' ');
                                lineStruct.addr = funcs[0];
                                lineStruct.binary = funcs[1];
                            }
                        }
                    } else {
                        lineStruct.addr = addr;
                        lineStruct.binary = value[0].trim();
                        lineStruct.type = value.length > 1 ? value[1] : '';
                        lineStruct.code = value.length > 2 ? value[2] : '';
                    }
                    lineMap.set(addrHex, lineStruct);
                    this.maxBinSize = Math.max(this.ctx!.measureText(lineStruct.addr + lineStruct.binary).width, this.maxBinSize);
                    this.addrArray.push(addrHex);
                    if (addrHex === hintAttr) this.hintLine = effectLint;
                    effectLint++;
                } catch (e) {
                    console.log(e);
                }
            }
        }
        return lineMap;
    }

    public showContent(content: string, hintAddr: string): void {
        this.loading!.style.display = "none";
        this.window!.style.display = "block";
        if (content.startsWith('error')) {
            this.window!.innerHTML = `<span class="column1" style="width:100%;text-align: center;">${content}</span>`;
            return;
        }
        let lineMap = this.getMap(content, hintAddr);
        this.maxBinSize = this.maxBinSize * 1.7;
        this.window!.innerHTML = '';
        for (let addr of this.addrArray) {
            if (!lineMap.has(addr)) continue;
            let struct = lineMap.get(addr);
            if (this.addrArray[this.hintLine] == addr) {
                this.window!.innerHTML += `<div class="line" id="emphasis" style = background:red">
                <span class="column0" style="width:${this.maxBinSize}px;">${struct!.addr} : ${struct!.binary}</span>
                <span class="column1" style="width:100px;">${struct!.type}</span>
                <span class="column2" style="width:300px;">${struct!.code}</span></div>`;
                (this.window!.querySelector("#emphasis") as HTMLElement)!.style.width = this.window!.scrollWidth + 'px';
                (this.window!.querySelector("#emphasis") as HTMLElement)!.style.background = '#0A59F7';
            } else {
                this.window!.innerHTML += `<div class="line">
                <span class="column0" style="width:${this.maxBinSize}px;">${struct!.addr} : ${struct!.binary}</span>
                <span class="column1" style="width:100px;">${struct!.type}</span>
                <span class="column2" style="width:300px;">${struct!.code}</span></div>`;
            }
        }
        this.window!.scrollTo(0, (this.hintLine - 1) * (this.shadowRoot!.querySelector("#window>.line")!.clientHeight) - this.window!.clientHeight / 2);
    }

    private resetCanvas(styleWidth: number, styleHeight: number, width: number, height: number): void {
        this.canvas!.style.width = styleWidth + "px";
        this.canvas!.style.height = styleHeight + "px";
        this.canvas!.width = width;
        this.canvas!.height = height;
    }

    public showLoading(): void {
        this.loading!.style.display = 'block';
        this.window!.style.display = 'none';
        this.style.display = 'block';
        this.style.position = 'absolute';
        this.style.left = '0px';
        this.style.border = '1px solid #d8d8d8';
    }

    initElements(): void {
        this.canvas = this.shadowRoot?.querySelector<HTMLCanvasElement>("#canvas");
        let close = this.shadowRoot?.querySelector("#close");
        this.window = this.shadowRoot?.querySelector("#window");
        this.loading = this.shadowRoot?.querySelector("#loading");
        this.ctx = this.canvas!.getContext('2d');
        this.resetCanvas(0, 0, 0, 0);
        close!.addEventListener("click", () => {
           if(this.close){
              this.close();
           }
            return true;
        });
    }

    initHtml(): string {
        return `
        <style>
            #close{
                position:absolute;
                top:0px;
                right: 0px;
                color: #D6D6D6;
            }
            #modal-wrap{
                position: absolute;
                top: 0;
                left: 0;
                width:100%;
                height:100%;
                background: var(--dark-background,#ffffff);
                z-index: 2000;
            }
            #window{
                overflow: auto;
                position: absolute;
                top: 21px;
                left: 0;
                width: calc(100% - 10px);
                height: calc(100% - 21px);
                padding-left: 10px;
            }
            #loading{
                position: absolute;
                left: calc(50% - 20px);
                top: calc(50% - 20px);
                width:40px;
                height:40px;
                transform: rotate(360deg);
                animation: rotation 2s linear infinite;
                -webkit-animation: rotation 2s linear infinite;
            }
            @keyframes rotation{
                from {
                    -webkit-transform: rotate(0deg);
                }
                to {
                    -webkit-transform: rotate(360deg);
                }
            } 
            .line{
                line-height:27px;
                white-space: nowrap;
            }
            span{
                display: inline-block;
            }
        </style>
        <div id="modal-wrap">
            <canvas id="canvas" style="display: none"> </canvas>
            <lit-icon id="close" name="close" size="20"> </lit-icon>
            <div id="window"> </div>
             <lit-icon id="loading" name="loading" size="40"> </lit-icon>
        </div>
        `;
    }
}

class Disassembling {
    addr = '';
    binary = '';
    type = '';
    code = '';
}