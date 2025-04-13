//
// Created by f2shafie on 12/05/24.
//

#include "mitigate_attack.h"
#include <set>
#include <map>
#include "smf_context.hpp"
#include "smf_app.hpp"
#include "smf_procedure.hpp"


extern smf::smf_app* smf_app_inst;

using namespace smf;

std::string get_current_time_m(int input) {
  auto now = std::chrono::system_clock::now();
  if (input >= 0) {
    now += std::chrono::minutes(input);
  }
  std::time_t now_time = std::chrono::system_clock::to_time_t(now);
  std::tm local_tm = *std::localtime(&now_time);
  std::ostringstream oss;
  oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
  return oss.str();
}
void release_ue_session(std::set <std::pair<int, int>>  toBanSessIDs){
  for (auto ids : toBanSessIDs) {
    std::shared_ptr<smf_pdu_session> sp = {};
    std::shared_ptr<smf_context> pc;
    bool found = smf_app_inst->seid_2_smf_context(ids.second, pc);
    if (!found) {
      Logger::nwdaf_sub().warn("[FATEMEH] SMF session context does not exist!");
    } else {
      auto supi = pc.get()->get_supi();
      std::string supi_str;
      supi_str.assign(supi.data, 16);
      auto nn = pc.get()->get_number_pdu_sessions();
      Logger::nwdaf_sub().warn("[FATEMEH] SMF session context found: %s %d", supi_str, nn);
    }

    {
      std::map<pdu_session_id_t, std::shared_ptr<smf_pdu_session>> sessMap;
      pc.get()->get_pdu_sessions(sessMap);
      Logger::nwdaf_sub().warn("Here is list of all pdu sessions");
      for (auto it : sessMap) {
        Logger::nwdaf_sub().warn("- PDU SESS ID: %d", it.first);
        auto s = it.second;
        auto ai = s.get()->get_snssai();
        Logger::nwdaf_sub().warn("- SNSSAI: %d %d", ai.sst, ai.sd);
        if (!pc.get()->find_pdu_session(it.first, sp)) {
          // error
          Logger::nwdaf_sub().warn("[FATEMEH] PDU session context does not exist!");
          continue;
        }
        auto proc = std::make_shared<session_release_sm_context_procedure>(sp);
        std::shared_ptr<smf_procedure> sproc = proc;


        std::shared_ptr<upf_graph> graph = sp->get_sessions_graph();
        if (!graph) {
          Logger::nwdaf_sub().warn("[FATEMEH] PDU session does not have a UPF association");
          continue;
        }
        smf_qos_flow empty_flow;
        graph->start_asynch_dfs_procedure(false, empty_flow);
        std::vector<edge> dl_edges;
        std::vector<edge> ul_edges;
        std::shared_ptr<pfcp_association> current_upf = {};
        if (proc->get_next_upf(dl_edges, ul_edges, current_upf) ==
            smf_procedure_code::ERROR) {
          Logger::nwdaf_sub().warn("[FATEMEH] Cannot find UPF!");
          continue ;
        }

        uint64_t seid = smf_app_inst->generate_seid();
        sp->set_seid(seid);
        proc->send_n4_session_deletion_request();
        Logger::nwdaf_sub().warn("[DSN_Latency_SMF] the request to release the PDU session has been sent: %s", get_current_time_m(-1));
      }
    }


  }

  return;
}
void manage_suspicious_session(std::vector<UEPduRatioPair> ueRatioList){
  Logger::nwdaf_sub().warn("[FATEMEH] In the manage suspicious session.");
  Logger::nwdaf_sub().warn("[FATEMEH] The UE ratio list is: %d", ueRatioList.size());
  std::set <std::pair<int, int>> toBanSessIDs;
  double Treshold = 0.90;
  for (int i=0; i<ueRatioList.size(); i++){

      toBanSessIDs.insert(std::make_pair(-1, ueRatioList[i].seId));
      Logger::nwdaf_sub().warn("[FATEMEH] The Ids are: %d %d", ueRatioList[i].seId);

  }
  if (toBanSessIDs.size()!=0){
    Logger::nwdaf_sub().warn("[FATEMEH] There are some suspicious UEs.");
    Logger::nwdaf_sub().warn("[DSN_Latency_SMF] Calling the release function to mitigate the risk! the time is: %s", get_current_time_m(-1));
    release_ue_session(toBanSessIDs);
  }


  return;

}