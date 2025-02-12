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

export class Smaps {
    tsNS: number = -1
    start_addr: string = ""
    end_addr: string = ""
    permission: string = ""
    path: string = ""
    size: number = 0
    rss: number = 0
    pss: number = 0
    reside: number = 0
    dirty: number = 0
    swapper: number = 0

    address: string = ""
    type: string = ""
    dirtyStr: string = ""
    swapperStr: string = ""
    rssStr: string = ""
    pssStr: string = ""
    sizeStr: string = ""
    resideStr: string = ""
}


export class SmapsTreeObj {
    constructor(id: string, pid: string, type: string) {
        this.id = id
        this.pid = pid
        this.type = type;
    }
    id: string = ""
    pid: string = ""
    rsspro: number = 0
    rssproStr: string = ""
    type: string = ""
    reg: number = 0
    regStr: string = ""
    path: string = ""
    rss: number = 0
    rssStr: string = ""
    dirty: number = 0
    dirtyStr: string = ""
    swapper: number = 0
    swapperStr: string = ""
    pss: number = 0
    pssStr: string = ""
    size: number = 0
    sizeStr: string = ""
    respro: number = 0
    resproStr: string = ""
    children: Array<SmapsTreeObj> = [];
}

