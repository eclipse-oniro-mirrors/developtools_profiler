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
import {SpRecordPerf} from "../../../../dist/trace/component/setting/SpRecordPerf.js";

describe('SpRecordPerf Test', ()=>{

    let spRecordPerf = new SpRecordPerf();
    it('SpRecordPerfTest01', function () {
        expect(spRecordPerf).not.toBeUndefined();
    });

    it('SpRecordPerfTest02', function () {
        expect(spRecordPerf.show).toBeFalsy();
    });

    it('SpRecordPerfTest03', function () {
        spRecordPerf.show = true;
        expect(spRecordPerf.show).toBeTruthy();
    });

    it('SpRecordPerfTest08', function () {
        spRecordPerf.show = false;
        expect(spRecordPerf.show).toBeFalsy();
    });

    it('SpRecordPerfTest09', function () {
        expect(spRecordPerf.startSamp).toBeFalsy();
    });

    it('SpRecordPerfTest10', function () {
        spRecordPerf.startSamp = true;
        expect(spRecordPerf.startSamp).toBeTruthy();
    });

    it('SpRecordPerfTest11', function () {
        spRecordPerf.startSamp = false;
        expect(spRecordPerf.startSamp).toBeFalsy();
    });

    it('SpRecordPerfTest05', function () {
        expect(spRecordPerf.unDisable()).toBeUndefined();
    });


    it('SpRecordPerfTest04', function () {
        expect(spRecordPerf.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: inline-block;
            width: 100%;
            height: 100%;
            background: var(--dark-background3,#FFFFFF);
            border-radius: 0px 16px 16px 0px;
        }

        .root {
            padding-top: 30px;
            padding-left: 54px;
            margin-right: 30px;
            font-size:16px;
            margin-bottom: 30px;
        }

        .config-div {
           width: 80%;
           display: flex;
           flex-direction: column;
           gap: 15px;
        }

        :host([show]) .config-div {
           display: flex;
           flex-direction: column;
           margin-bottom: 1vh;
        }

        :host(:not([show])) .config-div {
           margin-top: 5vh;
           margin-bottom: 5vh;
           gap: 25px;
        }

        :host(:not([show])) .hidden {
           display: none;
        }

        #addOptions {
           border-radius: 15px;
           border-color:rgb(0,0,0,0.1);
           width: 150px;
           height: 40px;
           font-family: Helvetica;
           font-size: 1em;
           color: #FFFFFF;
           text-align: center;
           line-height: 20px;
           font-weight: 400;
           margin-right: 20%;
           float: right;
        }
        
        :host(:not([startSamp])) #addOptions {
           background: #999999;
        }
        :host([startSamp]) #addOptions {
           background: #3391FF;
        }

        .title {
          opacity: 0.9;
          font-family: Helvetica-Bold;
          font-size: 18px;
          text-align: center;
          line-height: 40px;
          font-weight: 700;
          margin-right: 10px;
        }

        .des {
          opacity: 0.6;
          font-family: Helvetica;
          font-size: 14px;
          text-align: center;
          line-height: 35px;
          font-weight: 400;
        }

        .select {
          border-radius: 15px;
        }

        lit-switch {
          display:inline;
          float: right;
          height: 38px;
          margin-top: 10px;
        }
        input {
           height: 25px;
           outline:none;
           border-radius: 16px;
           text-indent:2%
        }
        input::-webkit-input-placeholder{
            color:var(--bark-prompt,#999999);
        }

        .input {
            border: 1px solid var(--dark-background5,#ccc);
            font-family: Helvetica;
            font-size: 14px;
            color: var(--dark-color1,#212121);
            text-align: left;
            line-height: 20px;
            font-weight: 400;
        }

        :host([startSamp]) .input {
            background: var(--dark-background5,#FFFFFF);
        }
        
        :host(:not([startSamp])) .input {
            color: #999999;
        }
     
        .sliderBody{
            width: 100%;
            height: min-content;
            display: grid;
            grid-template-columns: 1fr min-content;
        }

        .sliderInput {
            margin: 0 0 0 0;
            height: 40px;
            background-color: var(--dark-background5,#F2F2F2);
            -webkit-appearance:none;
            outline:0;
            font-size:14px;
            border-radius:20px;
            border:1px solid var(--dark-border,#c8cccf);
            color:var(--dark-color,#6a6f77);
            text-align: center;
        }
        </style>
        <div class=\\"root\\">
            <div class=\\"configList\\">
            </div>
            <button id =\\"addOptions\\">Advance Options</button>
        </div>
        "
`);
    });

    it('SpRecordPerfTest06', function () {
        expect(spRecordPerf.startSamp).toBeFalsy();
    });

    it('SpRecordPerfTest07', function () {
        spRecordPerf.startSamp = true
        expect(spRecordPerf.startSamp).toBeTruthy();
    });
})