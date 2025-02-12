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

import {convertJSON, LogicHandler} from "./ProcedureLogicWorkerCommon.js";

export class ProcedureLogicWorkerSPT extends LogicHandler {
    arrTs: Array<ThreadState> = [];
    arrTp: Array<ThreadProcess> = [];
    currentEventId: string = ""

    handle(data: any): void {
        this.currentEventId = data.id
        if (data && data.type) {
            switch (data.type) {
                case "spt-init":
                    this.getThreadState();
                    break;
                case "spt-getThreadStateData":
                    this.arrTs = convertJSON(data.params.list) || [];
                    this.getThreadProcessData()
                    break;
                case "spt-getThreadProcessData":
                    this.arrTp = convertJSON(data.params.list) || [];
                    this.initProcessThreadStateData();
                    break;
            }
        }
    }

    queryData(queryName: string, sql: string, args: any) {
        self.postMessage({
            id: this.currentEventId,
            type: queryName,
            isQuery: true,
            args: args,
            sql: sql
        })
    }

    getThreadState(){
        this.queryData("spt-getThreadStateData", `
    select itid,
       state,
       dur,
       ts,
       (ts - start_ts + dur) as end_ts,
       (ts - start_ts) as start_ts,
       cpu
from thread_state,trace_range where dur > 0 and (ts - start_ts) >= 0;
`, {});
    }

    getThreadProcessData(){
        this.queryData("spt-getThreadProcessData", `
    select A.id,
       A.tid as threadId,
       A.name as thread,
       IP.pid as processId,
       IP.name as process
from thread as A left join process as IP on A.ipid = IP.id
where IP.pid not null;
`, {});
    }

    getSPT(){
        this.queryData("spt-getStatesProcessThreadData", `
    select
      IP.name as process,
      IP.pid as processId,
      A.name as thread,
      B.state as state,
      A.tid as threadId,
      B.dur,
      (B.ts - TR.start_ts + B.dur) as end_ts,
      (B.ts - TR.start_ts) as start_ts,
      B.cpu
    from
      thread_state as B
    left join
      thread as A
    on
      B.itid = A.id
    left join
      process as IP
    on
      A.ipid = IP.id
    left join
      trace_range as TR
    where
      B.dur > 0
    and
      IP.pid not null
    and (B.ts - TR.start_ts) >= 0;
`, {});
    }

    initProcessThreadStateData() {
        let mapTp: Map<number, ThreadProcess> = new Map<number, ThreadProcess>();
        for (let tp of this.arrTp) {
            mapTp.set(tp.id, tp);
        }
        let sptArr:Array<SPT> = [];
        for (let tr of this.arrTs) {
            if (mapTp.has(tr.itid)) {
                let tp = mapTp.get(tr.itid);
                let spt = new SPT();
                spt.processId = tp!.processId
                spt.process = tp!.process
                spt.thread = tp!.thread
                spt.threadId = tp!.threadId
                spt.state = tr.state;
                spt.dur = tr.dur;
                spt.end_ts = tr.end_ts;
                spt.start_ts = tr.start_ts;
                spt.cpu = tr.cpu;
                sptArr.push(spt);
            }
        }
        this.arrTp = [];
        this.arrTs = [];
        self.postMessage({
            id: this.currentEventId,
            action: "spt-init",
            results: sptArr
        });
    }


}

export class ThreadState{
    itid:number = 0
    state:string = ""
    dur:number = 0
    ts:number = 0
    end_ts:number = 0
    start_ts:number = 0
    cpu:number = 0
}

export class ThreadProcess{
    id:number = 0
    threadId :number = 0
    thread :string = ""
    processId : number = 0
    process : string = ""
}

export class SPT {
    process: string = ""
    processId: number = 0
    thread: string = ""
    threadId: number = 0
    state: string = ""
    dur: number = 0
    start_ts: number = 0
    end_ts: number = 0
    cpu: number = 0;
    priority: string = "-"
    note: string = "-"
}
