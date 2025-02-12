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

export class SystemCpuSummary {
    startTime: number = -1
    startTimeStr: string = "";
    duration: number = -1
    durationStr: string = ""
    totalLoad: number = -1
    totalLoadStr: string = ""
    userLoad: number = -1
    userLoadStr: string = ""
    systemLoad: number = -1
    systemLoadStr: string = ""
    threads: number = -1
    threadsStr: string = ""
}

export class SystemDiskIOSummary {
    startTime: number = -1
    startTimeStr: string = ""
    duration: number = -1
    durationStr: string = ""
    dataRead: number = -1
    dataReadStr: string = ""
    dataReadSec: number = -1
    dataReadSecStr: string = ""
    dataWrite: number = -1
    dataWriteStr: string = ""
    dataWriteSec: number = -1
    dataWriteSecStr: string = ""
    readsIn: number = -1
    readsInStr: string = ""
    readsInSec: number = -1
    readsInSecStr: string = ""
    writeOut: number = -1
    writeOutStr: string = ""
    writeOutSec: number = -1
    writeOutSecStr: string = ""

}

export class ProcessHistory {
    processId: number = -1
    alive: string = '' // 0 alive and 1 dead
    firstSeen: string = ''
    firstSeenNumber: number = -1
    lastSeen: string = ''
    lastSeenNumber: number = -1
    processName: string = ""
    responsibleProcess: string = ""
    userName: string = ""
    cpuTime: string = ''
    cpuTimeNumber: number = -1
    pss: number = -1
}

export class LiveProcess {
    processId: number = -1
    processName: string = ""
    responsibleProcess: string = ""
    userName: string = ""
    cpu: string = ''
    threads: number = -1
    memory: string = ''
    memoryNumber: number = -1;
    diskWrite: number = -1
    diskReads: number = -1
    cpuTime: string = ""
    cpuTimeNumber: number = -1;
}

export class SystemNetworkSummary {
    startTime: number = -1
    startTimeStr: string = ""
    duration: number = -1
    durationStr: string = ""
    dataReceived: number = -1
    dataReceivedStr: string = ""
    dataReceivedSec: number = -1
    dataReceivedSecStr: string = ""
    dataSend: number = -1
    dataSendStr: string = ""
    dataSendSec: number = -1
    dataSendSecStr: string = ""
    packetsIn: number = -1
    packetsInStr: string = ""
    packetsInSec: number = -1
    packetsInSecStr: string = ""
    packetsOut: number = -1
    packetsOutStr: string = ""
    packetsOutSec: number = -1
    packetsOutSecStr: string = ""
}

export class SystemMemorySummary {
    startTimeStr: string = "0"
    durationStr: string = "0"
    durationNumber: number = -1
    memoryTotal: string = "0";
    memFree: string = "0";
    buffers: string = "0";
    cached: string = "0";
    shmem: string = "0";
    slab: string = "0";
    swapTotal: string = "0";
    swapFree: string = "0";
    mapped: string = "0";
    vmallocUsed: string = "0";
    pageTables: string = "0";
    kernelStack: string = "0";
    active: string = "0";
    inactive: string = "0";
    unevictable: string = "0";
    vmallocTotal: string = "0";
    sUnreclaim: string = "0";
    kReclaimable: string = "0";
    cmaTotal: string = "0";
    cmaFree: string = "0";
    zram: string = "0";
}