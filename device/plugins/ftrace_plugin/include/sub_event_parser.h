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
#ifndef SUB_EVENT_PARSER_H
#define SUB_EVENT_PARSER_H
#include <cstdint>
#include <functional>
#include <map>
#include "ftrace_field_parser.h"
#include "trace_plugin_result.pb.h"

FTRACE_NS_BEGIN
class SubEventParserRegisterar;
class SubEventParser {
public:
    static SubEventParser& GetInstance();

    bool IsSupport(uint32_t eventId) const;
    bool IsSupport(const std::string& eventName) const;
    bool ParseEvent(FtraceEvent& event, uint8_t data[], size_t size, const EventFormat& format) const;
    bool SetupEvent(const EventFormat& format);

    using ParseFunction = std::function<void(FtraceEvent&, uint8_t[], size_t, const EventFormat&)>;

protected:
    friend class SubEventParserRegisterar;
    void RegisterParseFunction(const std::string& name, ParseFunction&& func);
    void UnregisterParseFunction(const std::string& name);

private:
    SubEventParser();
    ~SubEventParser();
    DISALLOW_COPY_AND_MOVE(SubEventParser);
    std::map<uint32_t, ParseFunction> idToFunctions_;
    std::map<std::string, ParseFunction> nameToFunctions_;
};

class SubEventParserRegisterar {
public:
    SubEventParserRegisterar(const std::string& name, SubEventParser::ParseFunction&& func);
    ~SubEventParserRegisterar();

private:
    DISALLOW_COPY_AND_MOVE(SubEventParserRegisterar);
    std::string name_;
};
FTRACE_NS_END

#define REGISTER_FTRACE_EVENT_PARSE_FUNCTION(name, func) \
    static FTRACE_NS::SubEventParserRegisterar g_eventRegisterar##name(#name, func)

#endif // SUB_EVENT_PARSER_H
