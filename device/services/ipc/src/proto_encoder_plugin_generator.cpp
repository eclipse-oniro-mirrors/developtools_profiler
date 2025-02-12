/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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

#include "proto_encoder_plugin_generator.h"

using google::protobuf::FileDescriptor;
using google::protobuf::EnumDescriptor;
using google::protobuf::Descriptor;
using google::protobuf::io::Printer;
using google::protobuf::EnumValueDescriptor;
using google::protobuf::FieldDescriptor;

class OptGeneratorImpl {
public:
    explicit OptGeneratorImpl(const FileDescriptor* file) : fileContent_(file), printer_(nullptr) {}

    static std::string GetPrefix(const std::string& fileName)
    {
        std::string prefix = "";
        for (size_t i = 0; i < fileName.length(); i++) {
            if (fileName.c_str()[i] == '.') {
                break;
            }
            prefix += fileName.c_str()[i];
        }
        return prefix;
    }

    std::string SetNames(const std::string& fileName, const std::string& packageName)
    {
        fileName_ = fileName;
        packageName_ = packageName + "::";
        headFileName_ = "";

        for (size_t i = 0; i < fileName.length(); i++) {
            if (fileName.c_str()[i] == '.') {
                break;
            }
            headFileName_ += fileName.c_str()[i];
        }
        baseName_ = SwapName(headFileName_);
        return headFileName_;
    }

    // Swap variable style. e.g: cpu_plugin_config to cpuPluginConfig
    static std::string SwapName(const std::string& s)
    {
        std::string ret = "";
        bool b = true;
        for (size_t i = 0; i < s.length(); i++) {
            char c = s[i];
            if (c == '_') {
                b = true;
            } else if (b && islower(c)) {
                ret += (c + 'A' - 'a');
                b = false;
            } else {
                ret += c;
            }
        }
        return ret;
    }

    static std::string Tolowercase(const std::string& s)
    {
        std::string str = s;
        std::transform(str.begin(), str.end(), str.begin(), [](const char& c) {
            return std::tolower(c);
        });
        return str;
    }

    void GenHeader()
    {
        GenPrefix();
        GenerateEnum();
        GenerateClass();
        GenSurfix();
    }

    void GenPrefix()
    {
        printer_->Print("// Generated by protoencoder plugin.\n");
        printer_->Print("#pragma once\n");
        printer_->Print("#include \"base_message.h\"\n");

        for (int i = 0; i < fileContent_->dependency_count(); ++i) {
            printer_->Print("#include \"@name@.pbencoder.h\"\n", "name",
                            GetPrefix(fileContent_->dependency(i)->name()));
        }

        printer_->Print("namespace OHOS {\n");
        printer_->Print("namespace Developtools {\n");
        printer_->Print("namespace Profiler {\n");
        printer_->Print("namespace ProtoEncoder {\n");
    }

    void GenerateEnum()
    {
        for (int i = 0; i < fileContent_->enum_type_count(); ++i) {
            printer_->Print("enum @class@ : uint32_t {\n", "class", fileContent_->enum_type(i)->name());
            printer_->Indent();

            for (int j = 0; j < fileContent_->enum_type(i)->value_count(); ++j) {
                const EnumValueDescriptor* value = fileContent_->enum_type(i)->value(j);
                const std::string value_name = value->name();
                printer_->Print("@name@ = @number@,\n", "name", value_name, "number",
                                std::to_string(value->number()));
            }
            printer_->Outdent();
            printer_->Print("};\n");
        }
    }

    void GenerateNestClass(const Descriptor* message)
    {
        for (int i = 0; i < message->nested_type_count(); ++i) {
            const Descriptor* nestmessage = message->nested_type(i);
            GenerateNestClass(nestmessage);
            printer_->Print(
                "class @name@ : public BaseMessage {\n"
                " public:\n",
                "name", nestmessage->name());
            printer_->Indent();
            printer_->Print("@name@() = default;\n", "name", nestmessage->name());
            printer_->Print(
                "explicit @name@(RandomWriteCtx* writeCtx, MessagePool* messagePool = nullptr) : BaseMessage(writeCtx, messagePool) {}\n",
                "name", nestmessage->name());
            GenerateFieldsID(nestmessage);
            GenerateFunction(nestmessage);
            printer_->Outdent();
            printer_->Print("};\n\n");
        }
    }

    void GenerateClass()
    {
        // forward declaration
        for (int i = 0; i < fileContent_->message_type_count(); ++i) {
            const Descriptor* message = fileContent_->message_type(i);
            printer_->Print("class @name@;\n", "name", message->name());
        }

        for (int i = 0; i < fileContent_->message_type_count(); ++i) {
            const Descriptor* message = fileContent_->message_type(i);
            GenerateNestClass(message);

            printer_->Print(
                "class @name@ : public BaseMessage {\n"
                " public:\n",
                "name", message->name());
            printer_->Indent();
            printer_->Print("@name@() = default;\n", "name", message->name());
            printer_->Print(
                "explicit @name@(RandomWriteCtx* writeCtx, MessagePool* messagePool = nullptr) : BaseMessage(writeCtx, messagePool) {}\n",
                "name", message->name());
            GenerateFieldsID(message);
            GenerateFunction(message);
            printer_->Outdent();
            printer_->Print("};\n\n");
        }
    }

    void GenerateFieldsID(const Descriptor* message)
    {
        for (int i = 0; i < message->field_count(); ++i) {
            const FieldDescriptor* field = message->field(i);
            printer_->Print("static const uint32_t FIELDID_@name@ = @id@;\n",
                "name", field->name(), "id", std::to_string(field->number()));
        }
    }

    void GenerateFunction(const Descriptor* message)
    {
        // field->is_repeated()
        for (int i = 0; i < message->field_count(); ++i) {
            const FieldDescriptor* field = message->field(i);
            if (field->type() == FieldDescriptor::TYPE_MESSAGE) {
                printer_->Print("inline @typename@* @mora@_@name@()\n",
                    "mora", field->is_repeated()?"add":"mutable",
                    "typename", field->message_type()->name(),
                    "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("return AddSubMessage<@typename@>(FIELDID_@name@);\n",
                    "typename", field->message_type()->name(),
                    "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
            } else if (field->type() == FieldDescriptor::TYPE_BYTES) {
                printer_->Print("inline void set_@name@(const void* bytes, uint32_t size)\n",
                    "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("AddBytes(FIELDID_@name@, bytes, size);\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                printer_->Print("void set_@name@(GetDataCallback getData)\n", "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("return AddBytesByCallBack(FIELDID_@name@, getData);\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                printer_->Print("inline RandomWriteCtx* startAdd_@name@()\n", "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("return StartAddBytes(FIELDID_@name@);\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                printer_->Print("inline void finishAdd_@name@(int32_t size)\n", "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("return FinishAddBytes(size);\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
            } else if (field->type() == FieldDescriptor::TYPE_STRING) {
                printer_->Print("inline void @sora@_@name@(const std::string& str)\n",
                    "sora", field->is_repeated()?"add":"set",
                    "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("AddBytes(FIELDID_@name@, str.data(), str.size());\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                printer_->Print("inline void @sora@_@name@(std::string&& str)\n",
                    "sora", field->is_repeated()?"add":"set",
                    "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("AddBytes(FIELDID_@name@, str.data(), str.size());\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                printer_->Print("inline void @sora@_@name@(const char* str)\n",
                    "sora", field->is_repeated()?"add":"set",
                    "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("AddBytes(FIELDID_@name@, str, strlen(str));\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                printer_->Print("inline void @sora@_@name@(const char* str, uint32_t len)\n",
                    "sora", field->is_repeated()?"add":"set",
                    "name", Tolowercase(field->name()));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("AddBytes(FIELDID_@name@, str, len);\n", "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
            } else {
                // varint, fix32, fix64
                printer_->Print("inline void @sora@_@name@(@paramtype@ v)\n",
                    "sora", field->is_repeated()?"add":"set", "name", Tolowercase(field->name()),
                    "paramtype", GetParamType(field));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("@type@(FIELDID_@name@, v);\n", "type",
                    GetInnerType(field), "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
                // packed
                if (!field->is_repeated()) {
                    continue;
                }
                if (field->type() == FieldDescriptor::TYPE_SINT32 ||
                    field->type() == FieldDescriptor::TYPE_SINT64) {
                    perror("repeated signed(zigzag) fields are not supported in libprotobuf\n");
                    continue;
                }
                if (!field->is_packed()) {
                    continue;
                }
                printer_->Print("inline void add_@name@(const @paramtype@* array, uint32_t size)\n",
                    "name", Tolowercase(field->name()),
                    "paramtype", GetParamType(field));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("@type@(FIELDID_@name@, array, size);\n",
                    "type", GetInnerType(field, true), "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");

                printer_->Print("inline void add_@name@(const std::vector<@paramtype@>& array)\n",
                    "name", Tolowercase(field->name()),
                    "paramtype", GetParamType(field));
                printer_->Print("{\n");
                printer_->Indent();
                printer_->Print("@type@(FIELDID_@name@, array.data(), array.size());\n",
                    "type", GetInnerType(field, true), "name", field->name());
                printer_->Outdent();
                printer_->Print("}\n");
            }
        }
    }

    static std::string GetParamType(const FieldDescriptor* field)
    {
        switch (field->type()) {
            case FieldDescriptor::TYPE_BOOL:
                return "bool";
            case FieldDescriptor::TYPE_ENUM:
            case FieldDescriptor::TYPE_UINT32:
            case FieldDescriptor::TYPE_FIXED32:
                return "uint32_t";
            case FieldDescriptor::TYPE_INT32:
            case FieldDescriptor::TYPE_SINT32:
            case FieldDescriptor::TYPE_SFIXED32:
                return "int32_t";
            case FieldDescriptor::TYPE_INT64:
            case FieldDescriptor::TYPE_SINT64:
            case FieldDescriptor::TYPE_SFIXED64:
                return "int64_t";
            case FieldDescriptor::TYPE_UINT64:
            case FieldDescriptor::TYPE_FIXED64:
                return "uint64_t";
            case FieldDescriptor::TYPE_DOUBLE:
                return "double";
            case FieldDescriptor::TYPE_FLOAT:
                return "float";
            case FieldDescriptor::TYPE_STRING:
            case FieldDescriptor::TYPE_GROUP:
            case FieldDescriptor::TYPE_MESSAGE:
            case FieldDescriptor::TYPE_BYTES:
                return "";
            default:
                return "";
        }
        return "";
    }

    static std::string GetInnerType(const FieldDescriptor* field, bool packed = false)
    {
        switch (field->type()) {
            case FieldDescriptor::TYPE_BOOL:
            case FieldDescriptor::TYPE_ENUM:
            case FieldDescriptor::TYPE_INT32:
            case FieldDescriptor::TYPE_INT64:
            case FieldDescriptor::TYPE_UINT32:
            case FieldDescriptor::TYPE_UINT64:
                return packed ? "AddPackedVarint" : "AddVarint";
            case FieldDescriptor::TYPE_SINT32:
            case FieldDescriptor::TYPE_SINT64:
                return "AddZigZagVarint";
            case FieldDescriptor::TYPE_FIXED64:
            case FieldDescriptor::TYPE_SFIXED64:
            case FieldDescriptor::TYPE_DOUBLE:
                return packed ? "AddPackedFixed" : "AddFixed64";
            case FieldDescriptor::TYPE_FIXED32:
            case FieldDescriptor::TYPE_SFIXED32:
            case FieldDescriptor::TYPE_FLOAT:
                return packed ? "AddPackedFixed" : "AddFixed32";
            case FieldDescriptor::TYPE_STRING:
            case FieldDescriptor::TYPE_GROUP:
            case FieldDescriptor::TYPE_MESSAGE:
            case FieldDescriptor::TYPE_BYTES:
                return "";
            default:
                return "";
        }
        return "";
    }

    void GenSurfix()
    {
        printer_->Print("} // namespace ProtoEncoder\n");
        printer_->Print("} // namespace Profiler\n");
        printer_->Print("} // namespace Developtools\n");
        printer_->Print("} // namespace OHOS\n");
    }

    void SetPrinter(Printer* stub_h_printer)
    {
        printer_ = stub_h_printer;
    }
private:
    std::string fileName_ = "";
    std::string baseName_ = "";
    std::string packageName_ = "";
    std::string headFileName_ = "";
    std::vector<std::string> namespaces_;
    const FileDescriptor* const fileContent_;
    std::vector<const Descriptor*> stack_;
    std::vector<const EnumDescriptor*> enums_;
    Printer* printer_;
};

ProtoEncoderGenerator::ProtoEncoderGenerator() {}

ProtoEncoderGenerator::~ProtoEncoderGenerator() {}

bool ProtoEncoderGenerator::Generate(const google::protobuf::FileDescriptor* file,
                                     const std::string& parameter,
                                     google::protobuf::compiler::GeneratorContext* context,
                                     std::string* error) const
{
    auto pcsp = std::make_shared<OptGeneratorImpl>(file);
    std::string baseName = pcsp->SetNames(file->name(), file->package());
    std::unique_ptr<::google::protobuf::io::ZeroCopyOutputStream> headerOutput(context->Open(baseName +
                                                                                              ".pbencoder.h"));
    std::unique_ptr<::google::protobuf::io::ZeroCopyOutputStream> sourceOutput(context->Open(baseName +
                                                                                              ".pbencoder.cc"));
    Printer hPrinter(headerOutput.get(), '@');
    pcsp->SetPrinter(&hPrinter);
    pcsp->GenHeader();

    Printer ccPrinter(sourceOutput.get(), '@');
    ccPrinter.Print("// empty\n");
    return true;
}
