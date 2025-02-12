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
import {LitMainMenuGroup} from "../../base-ui/menu/LitMainMenuGroup.js";
import {LitMainMenu, MenuItem} from "../../base-ui/menu/LitMainMenu.js";
import {LitMainMenuItem} from "../../base-ui/menu/LitMainMenuItem";

@element('sp-help')
export class SpHelp extends BaseElement {
    private appContent: HTMLElement | undefined | null

    get dark() {
        return this.hasAttribute("dark");
    }

    set dark(dark: boolean) {
        if (dark) {
            this.setAttribute("dark", '' + dark);
        }
        this.appContent!.innerHTML = "<object type=\"text/html\" data="
            + "/application/doc/quickstart_hiprofiler_cmd.html?"
            + dark
            + " width=\"100%\" height=\"100%\"></object>"
    }

    initElements(): void {
        let that = this
        let parentElement = this.parentNode as HTMLElement;
        parentElement.style.overflow = 'hidden'
        this.appContent = this.shadowRoot?.querySelector('#app-content') as HTMLElement
        let mainMenu = this.shadowRoot?.querySelector('#main-menu') as LitMainMenu
        let header = mainMenu.shadowRoot?.querySelector('.header') as HTMLDivElement
        let version = mainMenu.shadowRoot?.querySelector('.version') as HTMLDivElement
        header.style.display = 'none'
        version.style.display = 'none'
        mainMenu.menus = [
            {
                collapsed: false,
                title: 'QuickStart',
                describe: '',
                children: [
                    {
                        title: "快速抓取trace说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data=" + "/application/doc/quickstart_hiprofiler_cmd.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "网页加载trace说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/quickstart_smartperf.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "Native Memory抓取和展示说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/native_memory.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "Ability Monitor抓取和展示说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/ability_monitor.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "Perf的抓取和展示说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/perf.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "Sql分析和Metrics说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/des_metris_support.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "在线抓取trace说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/capture_online.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "FileSystem抓取和展示说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/file_system.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "页内存抓取和展示说明", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/memory_fetching.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    }
                ]
            },
            {
                collapsed: false,
                title: 'TraceStreamer',
                describe: '',
                children: [
                    {
                        title: "TraceStreamer数据库说明",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/des_tables.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "编译Trace_streamer",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/compile_trace_streamer.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "TraceStreamer 解析数据状态表",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/des_stat.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "TraceStreamer支持解析事件列表",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/des_support_event.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "trace_streamer工具说明",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/quickstart_trace_streamer.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "binder事件上下文如何关联", icon: "", clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML =
                                "<object type=\"text/html\" data="
                                + "/application/doc/des_binder.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                    {
                        title: "wakeup唤醒说明",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/des_wakup.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    }
                ]
            },
            {
                collapsed: false,
                title: 'SmartPerf',
                describe: '',
                children: [
                    {
                        title: "SmartPerf 编译指导",
                        icon: "",
                        clickHandler: function (item: MenuItem) {
                            that.appContent!.innerHTML = "<object type=\"text/html\" data="
                                + "/application/doc/compile_smartperf.html?"
                                + that.dark
                                + " width=\"100%\" height=\"100%\"></object>"
                        }
                    },
                ]
            },
        ]
        mainMenu.style.width = '290px'
        let body = mainMenu.shadowRoot?.querySelector('.menu-body') as HTMLDivElement
        let groups = body.querySelectorAll<LitMainMenuGroup>('lit-main-menu-group')
        groups.forEach(value => {
            let items = value.querySelectorAll<LitMainMenuItem>('lit-main-menu-item')
            items.forEach(item => {
                item.style.width = '290px'
            })
            if(value.title == 'TraceStreamer'){
                let items = value.querySelectorAll<LitMainMenuItem>('lit-main-menu-item');
                items.forEach(i =>{
                    if(i.title != 'TraceStreamer数据库说明'){
                        i.style.display = 'none';
                    }
                })
            }
            if(value.title == 'SmartPerf'){
                value.style.display = 'none';
            }
        })
    }

    initHtml(): string {
        return `
        <style>
        :host{
            display: block;
            width: 100%;
            height: 100%;
            background-color: var(--dark-background5,#F6F6F6);
        }

        .container {
            display: grid;
            grid-template-columns: 1fr;
            grid-template-rows:1fr;
            background-color: var(--dark-background5,#F6F6F6);
            min-height: 100%;
        }

        .body{
            width: 90%;
            margin-left: 3%;
            margin-top: 2%;
            margin-bottom: 2%;
            display: grid;
            grid-template-columns: min-content  1fr;
            background-color: var(--dark-background3,#FFFFFF);
            border-radius: 16px 16px 16px 16px;
        }

        .content{
          background: var(--dark-background3,#FFFFFF);
          border-style: none none none solid;
          border-width: 1px;
          border-color: rgba(166,164,164,0.2);
          border-radius: 0px 16px 16px 0px;
          padding: 40px 20px 40px 20px;
          display: flex;
        }

        </style>
        <div class="container">
         <div class="body">
            <lit-main-menu id="main-menu" class="menugroup" data=''></lit-main-menu>
            <div id="app-content" class="content">
            </div>
         </div>
        </div>
        `;
    }
}