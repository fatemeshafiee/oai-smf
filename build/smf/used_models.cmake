
################################################################################
# Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The OpenAirInterface Software Alliance licenses this file to You under
# the OAI Public License, Version 1.1  (the "License"); you may not use this file
# except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.openairinterface.org/?page_id=698
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#-------------------------------------------------------------------------------
# For more information about the OpenAirInterface (OAI) Software Alliance:
#      contact@openairinterface.org
################################################################################

## This file is used to specify the common models and utils this library is using
## DO NOT JUST COPY THIS FILE FROM OTHER NFs. The reasoning behind this is to only compile used files to optimize
## build speed

# Add common model dependencies from SMF API model
# TODO here we also have stuff from NRF and PCF still mixed-in
list(APPEND USED_COMMON_MODEL_SRC_FILES
        ${COMMON_MODEL_DIR}/ProblemDetails.cpp
        ${COMMON_MODEL_DIR}/AccessTokenErr.cpp
        ${COMMON_MODEL_DIR}/AccessTokenReq.cpp
        ${COMMON_MODEL_DIR}/NFType.cpp
        ${COMMON_MODEL_DIR}/NFType_anyOf.cpp
        ${COMMON_MODEL_DIR}/LineType.cpp
        ${COMMON_MODEL_DIR}/LineType_anyOf.cpp
        ${COMMON_MODEL_DIR}/DnaiChangeType.cpp
        ${COMMON_MODEL_DIR}/DddTrafficDescriptor.cpp
        ${COMMON_MODEL_DIR}/NgApCause.cpp
        ${COMMON_MODEL_DIR}/DnaiChangeType_anyOf.cpp
        ${COMMON_MODEL_DIR}/InvalidParam.cpp
        ${COMMON_MODEL_DIR}/PatchOperation.cpp
        ${COMMON_MODEL_DIR}/PatchOperation_anyOf.cpp
        ${COMMON_MODEL_DIR}/PatchItem.cpp
        ${COMMON_MODEL_DIR}/RefToBinaryData.cpp
        ${COMMON_MODEL_DIR}/PlmnIdNid.cpp
        ${COMMON_MODEL_DIR}/ChangeItem.cpp
        ${COMMON_MODEL_DIR}/ChangeType.cpp
        ${COMMON_MODEL_DIR}/ChangeType_anyOf.cpp
        ${COMMON_MODEL_DIR}/BackupAmfInfo.cpp
        # SM Policy
        ${COMMON_MODEL_DIR}/AtsssCapability.cpp
        ${COMMON_MODEL_DIR}/PresenceState.cpp
        ${COMMON_MODEL_DIR}/PresenceState_anyOf.cpp
        ${COMMON_MODEL_DIR}/PduSessionType.cpp
        ${COMMON_MODEL_DIR}/PduSessionType_anyOf.cpp
        ${COMMON_MODEL_DIR}/RouteToLocation.cpp
        ${COMMON_MODEL_DIR}/RouteInformation.cpp
        ${COMMON_MODEL_DIR}/Ipv6Prefix.cpp
        ${COMMON_MODEL_DIR}/Ipv6Addr.cpp
        ${COMMON_MODEL_DIR}/Guami.cpp
        # RAN Node ID dependencies
        ${COMMON_MODEL_DIR}/GlobalRanNodeId.cpp
        ${COMMON_MODEL_DIR}/GNbId.cpp
        ${COMMON_MODEL_DIR}/TnapId.cpp
        # User Location Dependencies
        ${COMMON_MODEL_DIR}/UserLocation.cpp
        ${COMMON_MODEL_DIR}/NrLocation.cpp
        ${COMMON_MODEL_DIR}/Ncgi.cpp
        ${COMMON_MODEL_DIR}/N3gaLocation.cpp
        ${COMMON_MODEL_DIR}/TransportProtocol.cpp
        ${COMMON_MODEL_DIR}/TransportProtocol_anyOf.cpp
        ${COMMON_MODEL_DIR}/TwapId.cpp
        ${COMMON_MODEL_DIR}/HfcNodeId.cpp
        ${COMMON_MODEL_DIR}/EutraLocation.cpp
        ${COMMON_MODEL_DIR}/Ecgi.cpp
        # UTRAN/GERAN Location Dependencies
        ${COMMON_MODEL_DIR}/UtraLocation.cpp
        ${COMMON_MODEL_DIR}/GeraLocation.cpp
        ${COMMON_MODEL_DIR}/ServiceAreaId.cpp
        ${COMMON_MODEL_DIR}/LocationAreaId.cpp
        ${COMMON_MODEL_DIR}/RoutingAreaId.cpp
        ${COMMON_MODEL_DIR}/CellGlobalId.cpp
        # other dependencies
        ${COMMON_MODEL_DIR}/TraceData.cpp
        ${COMMON_MODEL_DIR}/TraceDepth.cpp
        ${COMMON_MODEL_DIR}/TraceDepth_anyOf.cpp
        ${COMMON_MODEL_DIR}/RatType.cpp
        ${COMMON_MODEL_DIR}/RatType_anyOf.cpp
        ${COMMON_MODEL_DIR}/SecondaryRatUsageReport.cpp
        ${COMMON_MODEL_DIR}/SecondaryRatUsageInfo.cpp
        ${COMMON_MODEL_DIR}/QosFlowUsageReport.cpp
        ${COMMON_MODEL_DIR}/VolumeTimedReport.cpp
        )

# we also use NRF models
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/nrf/nrf_model.cmake)

# finally, we have to include common_model.cmake (has to be last
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model/common_model.cmake)