@rem Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
@rem Licensed under the Apache License, Version 2.0 (the "License");
@rem you may not use this file except in compliance with the License.
@rem You may obtain a copy of the License at
@rem
@rem     http://www.apache.org/licenses/LICENSE-2.0
@rem
@rem Unless required by applicable law or agreed to in writing, software
@rem distributed under the License is distributed on an "AS IS" BASIS,
@rem WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
@rem See the License for the specific language governing permissions and
@rem limitations under the License.
@echo off
set DIR="%cd%"
echo DIR=%DIR%
hdc_std shell mkdir -p /data/test/resource/testdata/
for /R %DIR% %%f in (testdata\*) do (
hdc_std file send %%f /data/test/resource/testdata/
echo %%f
)

call send_dwarf_to_device.bat

call send_report_to_device.bat

pause