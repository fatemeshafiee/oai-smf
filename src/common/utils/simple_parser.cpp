/* From https://gist.github.com/javiermon/6272065#file-gateway_netlink-c */
/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "simple_parser.hpp"
#include "logger.hpp"

bool simple_parser::parse(const std::string &str) {
  std::string CRLF = "\r\n";
  Logger::smf_app().debug("");
  Logger::smf_app().debug("Simple parser, parsing a string:");
  Logger::smf_app().debug("%s", str.c_str());

  //find boundary
  std::size_t content_type_pos = str.find("Content-Type");  //first part
  if ((content_type_pos <= 4) or (content_type_pos == std::string::npos))
    return false;

  std::string boundary_str = str.substr(2, content_type_pos - 4);  // 2 for -- and 2 for CRLF
  Logger::smf_app().debug("Boundary: %s", boundary_str.c_str());
  std::string boundary_full = "--" + boundary_str + CRLF;
  std::string last_boundary = "--" + boundary_str + "--" + CRLF;

  std::size_t crlf_pos = str.find(CRLF, content_type_pos);
  std::size_t boundary_pos = str.find(boundary_full);
  std::size_t boundary_last_post = str.find(last_boundary);

  while (boundary_pos < boundary_last_post) {
    mime_part p = { };
    content_type_pos = str.find("Content-Type", boundary_pos);
    crlf_pos = str.find(CRLF, content_type_pos);
    if ((content_type_pos == std::string::npos)
        or (crlf_pos == std::string::npos))
      break;
    p.content_type = str.substr(content_type_pos + 14,
                                crlf_pos - (content_type_pos + 14));
    Logger::smf_app().debug("Content Type: %s", p.content_type.c_str());

    crlf_pos = str.find(CRLF + CRLF, content_type_pos);  //beginning of content
    boundary_pos = str.find(boundary_full, crlf_pos);
    if (boundary_pos == std::string::npos) {
      boundary_pos = str.find(last_boundary, crlf_pos);
    }
    if (boundary_pos > 0) {
      p.body = str.substr(crlf_pos + 4, boundary_pos - 2 - (crlf_pos + 4));
      Logger::smf_app().debug("Body: %s", p.body.c_str());
      mime_parts.push_back(p);
    }
  }
  return true;
}

void simple_parser::get_mime_parts(std::vector<mime_part> &parts) const {
  for (auto it : mime_parts) {
    parts.push_back(it);
  }

}
