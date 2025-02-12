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

@element('sp-filter')
export class SpFilter extends BaseElement {
    initElements(): void {
    }

    initHtml(): string {
        return `
        <style>
        :host{
            width:100%;
        }

        .root{
            display: flex;
            align-items: center;
            padding: 0px 12px 0px 12px;
            height: 24px;
            z-index: 3;
            background-color: var(--dark-background5,#F2F2F2);
        }
        .search{
            display: flex;
            align-items: center;
            border: 1px solid rgba(0,0,0,0.60);
            border-radius: 8px;
            width: 356px;
            height: 16px;
            background-color: var(--dark-background5,#FFFFFF);
            margin-left: 13px;
        }
        .inputFilter{
            opacity: 0.86;
            font-family: Helvetica;
            font-size: 14px;
            text-align: left;
            line-height: 16px;
            font-weight: 400;
            width: 67px;
        }
        ::-webkit-input-placeholder{
            font-size:12px;
        }
        .image{
            width: 20px;
            height: 12px;
            margin-left: 8px;
            margin-right: 8px;
        }
        .input{
            border:none;
            width: 100%;
            margin-right: 8px;
            font-size: 12px;
            background-color: var(--dark-background,#FFFFFF);
            outline:none;
        }
        </style>
        <div class="root">
         <span class="inputFilter">Input Filter</span>
         <div class="search">
           <img src="img/screening.png" class="image">
           <input placeholder="Detail Filter" class="input"/>
        </div>
        </div>
        `;
    }
}