/*
* Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef PROJECTION_TREE_H
#define PROJECTION_TREE_H

#include <iostream>
#include <unordered_map>
#include <vector>

#include "doc_errno.h"
#include "json_common.h"
#include "rd_log_print.h"

namespace DocumentDB {
struct ProjectionNode {
    std::unordered_map<std::string, ProjectionNode *> sonNode;
    bool isDeepest;
    int Deep;
    ProjectionNode()
    {
        Deep = 0;
        isDeepest = true;
    }
    int DeleteProjectionNode();
    ~ProjectionNode()
    {
        DeleteProjectionNode();
    }
};
class ProjectionTree {
public:
    int ParseTree(std::vector<std::vector<std::string>> &path);
    bool SearchTree(std::vector<std::string> &singlePath, size_t &index);

private:
    ProjectionNode node_;
};
} // namespace DocumentDB
#endif // PROJECTION_TREE_H