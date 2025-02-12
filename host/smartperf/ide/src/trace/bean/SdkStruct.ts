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

import {BaseStruct} from "./BaseStruct.js";

export class SdkSliceStruct extends BaseStruct {
    static maxSdkSlice: number = 0
    static maxSdkSliceName: string = ""
    static hoverSdkSliceStruct: SdkSliceStruct | undefined;
    static selectSdkSliceStruct: SdkSliceStruct | undefined;
    static sdkName: number = 0


    value: number | undefined
    start_ts: number | undefined
    end_ts: number | undefined
    slice_message: string | undefined
}

export class CounterStruct extends BaseStruct {
    static maxCounter: number = 0
    static maxCounterName: string = ""
    static hoverCounterStruct: CounterStruct | undefined;
    static selectCounterStruct: CounterStruct | undefined;

    value: number | undefined
    ts: number | undefined
    counter_id: number | undefined
}