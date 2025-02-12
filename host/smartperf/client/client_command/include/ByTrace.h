/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef BY_TRACE_H
#define BY_TRACE_H
#include "common.h"
namespace OHOS {
namespace SmartPerf {
class ByTrace {
public:
    static ByTrace &GetInstance()
    {
        static ByTrace instance;
        return instance;
    }
    // trace配置
    void SetTraceConfig(int mSum, int mInterval, long long mThreshold, int mLowfps, int mCurNum) const;
    // 开始抓trace线程
    void ThreadGetTrace() const;
    // trace命令配置
    void SetTraceCmd(std::string traceCmd) const;
    // 校验fps-jitters
    TraceStatus CheckFpsJitters(std::vector<long long> jitters, int cfps);
    // 触发trace
    void TriggerCatch(long long curTime) const;

private:
    ByTrace() {};
    ByTrace(const ByTrace &);
    ByTrace &operator = (const ByTrace &);

    // 抓trace总次数 默认2次
    mutable int sum = 2;
    // 当前触发的次数
    mutable int curNum = 1;
    // 抓trace间隔(两次抓取的间隔时间 默认60*1000 ms)
    mutable int interval = 60000;
    // 抓trace触发条件:默认 某一帧的某个jitter>100 ms触发
    mutable long long threshold = 100;
    // 上一次触发时间
    mutable long long lastTriggerTime = -1;
    // 当前是否触发
    mutable long long currentTrigger = -1;
    //traceCmd
    mutable std::string traceCmd = "";
    //低帧触发
    mutable int lowfps = -1;
    //前2秒采的不准
    mutable int times = 0;
};
}
}
#endif