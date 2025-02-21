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

import {BaseElement, element} from "../BaseElement.js";
import {LitCheckBox} from "./LitCheckBox.js";

@element('lit-check-group')
export class LitCheckGroup extends BaseElement {

    get direction() {
        return this.getAttribute("direction")
    }

    get value(): Array<string> {
        let values = []
        for (const litCheckBoxElement of this.querySelectorAll<LitCheckBox>('lit-check-box[checked]')) {
            values.push(litCheckBoxElement.value)
        }
        return values;
    }

    initElements(): void {
    }

    initHtml(): string {
        return `
        <style>   
        :host {
            display: -webkit-flex; 
            display: flex;
            flex-direction: column;
        }
        :host([direction]) {
            flex-direction: ${this.direction};
        }
        :host(:not([direction])) {
            flex-direction: column;
        }
        
        :host([layout="compact"]) {
            gap:5px;
        }
        :host([layout="dispersion"]) {
           gap:10px;
        }
        
        </style>
        <slot class="check-group"></slot>`;
    }
}