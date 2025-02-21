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
import {HeapTreeDataBean} from "../../../dist/trace/bean/HeapTreeDataBean.js"

describe('HeapTreeDataBean Test', ()=>{
    let heapTreeDataBean  = new HeapTreeDataBean();

    it('HeapTreeDataBeanTest01', function () {
        heapTreeDataBean = {
            MoudleName: "MoudleName",
            AllocationFunction: "AllocationFunction",
            startTs: 0,
            endTs: 0,
            eventType: "eventType",
            depth: 0,
            heapSize: 0,
            eventId: "eventId",
        }
        expect(heapTreeDataBean).not.toBeUndefined()
        expect(heapTreeDataBean).toMatchInlineSnapshot({
  MoudleName: expect.any(String),
  AllocationFunction: expect.any(String),
  startTs: expect.any(Number),
  endTs: expect.any(Number),
  eventType: expect.any(String),
  depth: expect.any(Number),
  heapSize: expect.any(Number),
  eventId: expect.any(String) }, `
Object {
  "AllocationFunction": Any<String>,
  "MoudleName": Any<String>,
  "depth": Any<Number>,
  "endTs": Any<Number>,
  "eventId": Any<String>,
  "eventType": Any<String>,
  "heapSize": Any<Number>,
  "startTs": Any<Number>,
}
`)
    });
})