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

import {BaseElement, element} from "../../base-ui/BaseElement.js";
import "../../base-ui/popover/LitPopover.js"
import {LitPopover} from "../../base-ui/popover/LitPopover.js";

@element('sp-text')
export class SpText extends BaseElement {
    initElements(): void {
        let litPopover = this.shadowRoot?.querySelector<LitPopover>('lit-popover');
        litPopover!.dataSource = [{
            text: "# Samples",
            isSelected: true
        },]
    }

    initHtml(): string {
        return `
        <style>
        :host{
        }
        .root{
            display: flex;
            flex-direction: column;
        }
        .trace-menu{
            grid-area: m;
        }
        .trace-content{
            grid-area: b;
            width: 100%;
            height: 2000px;
            overflow: auto;
        }
        </style>
        <div class="root">
            <div id="trace-content" class="trace-content">
            <img src="img/pic.png">
            <lit-popover direction="topleft" type="multiple-text" title="">
              <button>test</button>
            </lit-popover>
            </div>
        </div>
        `;
    }
}