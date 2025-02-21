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
import {WakeUpTimeBean} from "../../../dist/trace/bean/WakeUpTimeBean.js"

describe('WakeUpTimeBean Test', () => {
    let wakeUpTimeBean = new WakeUpTimeBean();
    it('wakeUpTimeBean', function () {
        wakeUpTimeBean = {
            wakeTs: 0,
            startTs: 0,
            preRow: 0
        };
        expect(wakeUpTimeBean).not.toBeUndefined()
        expect(wakeUpTimeBean).toMatchInlineSnapshot({
  wakeTs: expect.any(Number),
  startTs: expect.any(Number),
  preRow: expect.any(Number) }, `
Object {
  "preRow": Any<Number>,
  "startTs": Any<Number>,
  "wakeTs": Any<Number>,
}
`);
    });
})
