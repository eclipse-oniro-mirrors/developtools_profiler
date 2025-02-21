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

import {CpuFreqLimitsStruct} from "../database/ui-worker/ProcedureWorkerCpuFreqLimits.js";

export class SelectionParam {
    recordStartNs:number = 0
    leftNs: number = 0;
    rightNs: number = 0;
    hasFps: boolean = false;
    statisticsSelectData: any = undefined
    fileSystemVMData: any = undefined
    perfAll: boolean = false;
    fileSysVirtualMemory: boolean = false;
    diskIOLatency:boolean = false;

    cpus: Array<number> = [];
    cpuStateFilterIds: Array<number> = [];
    cpuFreqFilterIds: Array<number> = [];
    cpuFreqLimitDatas:Array<Array<CpuFreqLimitsStruct>> = [];
    threadIds: Array<number> = [];
    processTrackIds: Array<number> = [];
    virtualTrackIds: Array<number> = [];
    funTids: Array<number> = [];
    funAsync: Array<{name:string,pid:number}> = [];
    heapIds: Array<number> = [];
    nativeMemory: Array<String> = [];
    cpuAbilityIds: Array<string> = []
    memoryAbilityIds: Array<string> = []
    diskAbilityIds: Array<string> = []
    networkAbilityIds: Array<string> = []
    perfSampleIds: Array<number> = [];
    perfCpus: Array<number> = [];
    perfProcess: Array<number> = [];
    perfThread: Array<number> = [];
    fileSystemType:Array<number> = [];
    sdkCounterIds: Array<string> = [];
    sdkSliceIds: Array<string> = [];
    diskIOipids:Array<number> = [];
    systemEnergy: Array<string> = []
    powerEnergy: Array<string> = []
    anomalyEnergy: Array<string> = []
    smapsType:Array<string> = [];
}

export class BoxJumpParam {
    leftNs: number = 0;
    rightNs: number = 0;
    state: string = "";
    processId: number = 0;
    threadId: number = 0;
}

export class SelectionData {
    name: string = ""
    process: string = ""
    pid: string = ""
    thread: string = ""
    tid: string = ""
    wallDuration: number = 0
    avgDuration: string = ""
    occurrences: number = 0
    state: string = ""
    trackId: number = 0
    delta: string = ""
    rate: string = ""
    avgWeight: string = ""
    count: string = ""
    first: string = ""
    last: string = ""
    min: string = ""
    max: string = ""
    stateJX: string = ""
}

export class Counter {
    id: number = 0
    trackId: number = 0
    name: string = ""
    value: number = 0
    startTime: number = 0
}

export class Fps {
    startNS: number = 0
    timeStr: string = ""
    fps: number = 0
}