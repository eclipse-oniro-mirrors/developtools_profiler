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
import {LitMainMenu} from "../../../dist/base-ui/menu/LitMainMenu.js";
import {MenuItem} from "../../../src/base-ui/menu/LitMainMenu.js";

describe("LitMainMenu Test", () => {

    it('LitMainMenu01', () => {
        let litMainMenu = new LitMainMenu();
        expect(litMainMenu).not.toBeUndefined()
        expect(litMainMenu).not.toBeNull()
    });

    it('LitMainMenu01', () => {
        let litMainMenu = new LitMainMenu();
        expect(litMainMenu).not.toBeUndefined()
        expect(litMainMenu).not.toBeNull()
    });

    it('LitMainMenu02', () => {
        let litMainMenu = new LitMainMenu();
        litMainMenu.menus = [
            {
                collapsed: false,
                title: 'Navigation',
                describe: 'Open or record a new trace',
                children: [
                    {
                        title: "Open trace file",
                        icon: "folder",
                        fileChoose: true,
                        fileHandler: function (ev: InputEvent) {
                        }

                    },
                    {
                        title: "Record new trace", icon: "copyhovered", clickHandler: function (item: MenuItem) {
                        }
                    }
                ]
            }
        ]
        expect(litMainMenu.menus.length).toBe(1)
    });

    it('LitMainMenu03', () => {
        let litMainMenu = new LitMainMenu();
        expect(litMainMenu.initHtml()).toMatchInlineSnapshot(`
"
        <style>
        :host{
            display: flex;
            flex-direction: column;
            width: 248px;
            background-color: var(--dark-background,#FFFFFF);
            height: 100vh;
        }
        .menu-body ::-webkit-scrollbar-track
        {
            border-radius:10px;
            background-color:#F5F5F5;
        }
        .menu-body ::-webkit-scrollbar-thumb
        {
            border-radius:10px;
            background-color: var(--dark-background,#FFFFFF);

        }
        .header{
            display: grid;
            background-color: var(--dark-background1,#FFFFFF);
            border-bottom: 1px solid var(--dark-background1,#EFEFEF);
            color: #47A7E0;
            font-size: 1.4rem;
            padding-left: 20px;
            /*padding-right: 10px;*/
            gap: 0 20px;
            box-sizing: border-box;
            width: 100%;
            height: 56px;
            grid-template-columns: min-content 1fr min-content;
            grid-template-rows: auto;
        }
        .header *{
            align-self: center;
            user-select: none;
        }
        .version{
            color: #94979d;
            padding: 20px;
            font-size: 0.6rem;
            width: 100%;
            text-align: right;
        }
        *{
            box-sizing: border-box;
        }
        .menu-button{
            height: 47px;
            width: 48px;
            display: flex;
            align-content: center;
            justify-content: right;
            cursor: pointer;
        }
        </style>
        <div name=\\"header\\" class=\\"header\\">
            <img src=\\"img/logo.png\\"/>
                <div class=\\"menu-button\\">
                    <lit-icon name=\\"menu\\" size=\\"20\\" color=\\"var(--dark-color1,#4D4D4D)\\"></lit-icon>
                </div>
            </div>
            <div class=\\"menu-body\\" style=\\"overflow: auto;overflow-x:hidden;height: 100%\\">
                <slot id=\\"st\\" ></slot>
            </div>
        <div class=\\"version\\" style=\\"\\">
        </div>
        "
`);
    });

    it('LitMainMenu04', () => {
        let litMainMenu = new LitMainMenu();
        litMainMenu.menus = [
            {
                collapsed: true,
                title: 'Navigation',
                describe: 'Open or record a new trace',
                children: [
                    {
                        title: "Open trace file",
                        icon: "folder",
                        fileChoose: true,
                        fileHandler: function (ev: InputEvent) {
                        }

                    },
                    {
                        title: "Record new trace", icon: "copyhovered", clickHandler: function (item: MenuItem) {
                        }
                    }
                ]
            }
        ]
        expect(litMainMenu.menus.length).toBe(1)
    });
})
