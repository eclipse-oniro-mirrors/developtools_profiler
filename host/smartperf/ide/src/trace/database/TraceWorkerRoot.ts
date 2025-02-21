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
 
let worker:Worker;
self.onmessage = (e)=>{
    if (e.data.action === "open") {
        worker = new Worker("TraceWorker.js")
        worker.onmessage = (msg)=>{
            self.postMessage(msg.data);
        }
        worker.postMessage(e.data,[e.data.buffer]);
    } else if (e.data.action === "exec") {
        worker.postMessage(e.data);
    } else if (e.data.action == "exec-buf") {
        // @ts-ignore
        worker.postMessage(e.data);
    }
}
self.onerror = event => {
    worker.terminate();
}
self.onclose = () => {
    worker.terminate();
}