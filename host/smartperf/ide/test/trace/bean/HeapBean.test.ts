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
import {HeapBean} from "../../../dist/trace/bean/HeapBean.js"

describe('HeapBean Test', ()=>{
    let heapBean = new HeapBean();

    it('HeapBeanTest01', function () {
        heapBean = {
            MoudleName: "MoudleName",
            AllocationFunction: "AllocationFunction",
            Allocations: 0,
            Deallocations: 0,
            AllocationSize: 0,
            DeAllocationSize: 0,
            Total: 0,
            RemainingSize: 0,
            depth: 0,
        }
        expect(heapBean).not.toBeUndefined()
        expect(heapBean).toMatchInlineSnapshot({
  MoudleName: expect.any(String),
  AllocationFunction: expect.any(String),
  Allocations: expect.any(Number),
  Deallocations: expect.any(Number),
  AllocationSize: expect.any(Number),
  DeAllocationSize: expect.any(Number),
  Total: expect.any(Number),
  RemainingSize: expect.any(Number),
  depth: expect.any(Number) }, `
Object {
  "AllocationFunction": Any<String>,
  "AllocationSize": Any<Number>,
  "Allocations": Any<Number>,
  "DeAllocationSize": Any<Number>,
  "Deallocations": Any<Number>,
  "MoudleName": Any<String>,
  "RemainingSize": Any<Number>,
  "Total": Any<Number>,
  "depth": Any<Number>,
}
`)
    });
})