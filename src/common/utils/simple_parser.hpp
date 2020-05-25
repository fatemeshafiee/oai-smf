/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file simple_parser.hpp
 \brief
 \author
 \company Eurecom
 \email:
 */
#ifndef FILE_SIMPLE_PARSER_HPP_SEEN
#define FILE_SIMPLE_PARSER_HPP_SEEN
# include <string>
#include <map>
#include <vector>

typedef struct mime_part {
  std::string content_type;
  std::string body;
} mime_part;

class simple_parser {
 public:
  bool parse(const std::string &str);
  void get_mime_parts(std::vector<mime_part> &parts) const;
 private:
  std::vector<mime_part> mime_parts;

};

#endif /* FILE_SIMPLE_PARSER_HPP_SEEN */
