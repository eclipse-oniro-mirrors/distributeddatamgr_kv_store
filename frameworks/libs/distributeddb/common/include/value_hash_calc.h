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

#ifndef VALUE_HASH_CALC_H
#define VALUE_HASH_CALC_H

#include <vector>
#include "db_types.h"

namespace DistributedDB {
class ValueHashCalc {
public:
    ValueHashCalc();
    ~ValueHashCalc();
    ValueHashCalc(const ValueHashCalc &) = delete;
    ValueHashCalc &operator=(const ValueHashCalc &) = delete;
    int Initialize() const;
    int Update(const std::vector<uint8_t> &value) const;
    int GetResult(std::vector<uint8_t> &value) const;

private:
    struct ValueHashCalcContext;
    ValueHashCalcContext *context_;
};
}

#endif // VALUE_HASH_CALC_H
