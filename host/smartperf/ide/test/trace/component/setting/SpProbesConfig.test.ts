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
import {SpProbesConfig} from "../../../../dist/trace/component/setting/SpProbesConfig.js";
import {LitCheckBox} from "../../../../src/base-ui/checkbox/LitCheckBox";

describe('SpProbesConfig Test', ()=>{
    beforeAll(() => {
        document.body.innerHTML =  `
            <probes-config id = "spconfig"><probes-config>
        `
    })
    it('new SpProbesConfig', function () {
        expect(new SpProbesConfig()).not.toBeNull();
    });

    it(' SpProbesConfig get Default attrValue', function () {
        let spEle = document.querySelector("#spconfig") as SpProbesConfig
        expect(spEle.traceConfig).toEqual([])
        expect(spEle.traceEvents).toEqual([])
        expect(spEle.memoryConfig).toEqual([])
    });

    it(' SpProbesConfig test', function () {
        let spEle = document.querySelector("#spconfig") as SpProbesConfig
        expect(spEle.initHtml()).toMatchInlineSnapshot(`
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
        .recordText {
           font-family: Helvetica-Bold;
           font-size: 1em;
           color: var(--dark-color1,#000000);
           line-height: 28px;
           font-weight: 700;
           margin-bottom: 20px;
        }

        .config-page {
            height: 95%;
            font-size: 0.875em;
        }

        .trace-config{
           display: grid;
           grid-template-columns: repeat(2, 1fr);
           gap: 10px;
           margin-bottom: 20px;
        }

        .memory-config{
           display: grid;
           grid-template-columns: repeat(2, 1fr);
           border-style: solid none none none;
           border-color: #D5D5D5;
           padding-top: 15px;
           margin-top: 15px;
           gap: 10px;
        }

        .span-col-2{
           grid-column: span 2 / auto;
        }

        .log-config{
           display: grid;
           grid-template-columns: repeat(2, 1fr);
           border-style: solid none none none;
           border-color: #D5D5D5;
           padding-top: 15px;
           gap: 10px;
        }

        #hitrace-cat{
           display: grid;
           grid-template-columns: 1fr 1fr;
        }
        .user-events{
           display: grid;
           grid-template-columns: repeat(4, 1fr);
           grid-template-rows: repeat(2, 1fr);
           gap: 10px;
           margin-left: 15px;;
        }
        </style>
        <div class=\\"root\\">
            <div class=\\"recordText\\" >Record mode</div>
            <div class=\\"config-page\\">
                <div>
                    <div class=\\"trace-config\\"></div>
                    <div class=\\"span-col-2\\" id=\\"hitrace-cat\\">
                      <check-des-box id=\\"hitrace\\" value =\\"Hitrace categories\\" des=\\"Enables C++ codebase annotations (HTRACE_BEGIN() / os.Trace())\\">
                      </check-des-box>
                      <div class=\\"user-events\\">
                          <slot></slot>
                      </div>
                    </div>
                </div>
                <div class=\\"memory-config\\">
                    <div class=\\"span-col-2\\">
                      <span>Memory Config</span>
                    </div>
                </div>
            </div>
        </div>
        "
`);
    });
})