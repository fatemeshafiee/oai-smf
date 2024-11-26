//
// Created by f2shafie on 12/05/24.
//

#ifndef OAI_SMF_MITIGATE_ATTACK_H
#define OAI_SMF_MITIGATE_ATTACK_H
#include <string>
#include <set>
#include <vector>
#include <utility>

struct UEPduRatioPair {
  std::string ueIP;
//  int pduSessId;
  int seId;
//  double ratio;

};
std::string get_current_time_m(int input);
void release_ue_session(std::set<std::pair<int, int>> toBanSessIDs);
void manage_suspicious_session(std::vector<UEPduRatioPair> ueRatioList);
#endif  // OAI_SMF_MITIGATE_ATTACK_H
