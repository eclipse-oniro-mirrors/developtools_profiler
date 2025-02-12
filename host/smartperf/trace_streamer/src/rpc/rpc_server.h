/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef RPC_RPC_H
#define RPC_RPC_H

#include <functional>
#include <mutex>
#include "trace_streamer_selector.h"
namespace SysTuning {
namespace TraceStreamer {
class RpcServer {
public:
    using ResultCallBack = std::function<void(const std::string /* result */, int)>;

    using SendDataCallBack = std::function<void(const char*, int, int)>;
    // In order to bind HTTP, maintain a unified interface, even if some parameters are useless
    bool ParseData(const uint8_t* data, size_t len, ResultCallBack resultCallBack);
    bool ParseDataOver(const uint8_t* data, size_t len, ResultCallBack resultCallBack);
    bool SqlOperate(const uint8_t* data, size_t len, ResultCallBack resultCallBack);
    bool SqlQuery(const uint8_t* data, size_t len, ResultCallBack resultCallBack);
    bool Reset(const uint8_t* data, size_t len, ResultCallBack resultCallBack);
    void CancelSqlQuery();

    // only for wasm, no callback
    int WasmSqlQuery(const uint8_t* data, size_t len, uint8_t* out, int outLen);
    int WasmSqlQueryWithCallback(const uint8_t* data, size_t len, ResultCallBack callback) const;
    int UpdateTraceTime(const uint8_t* data, int len);
    int TraceStreamer_Init_ThirdParty_Config(const uint8_t* data, int len);
    std::map<int, std::string> g_thirdPartyConfig;
private:
    std::unique_ptr<TraceStreamerSelector> ts_ = std::make_unique<TraceStreamerSelector>();
    size_t lenParseData_ = 0;
};
} // namespace TraceStreamer
} // namespace SysTuning
#endif // RPC_RPC_H
