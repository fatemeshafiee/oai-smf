/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-PDU-Descriptions"
 * 	found in "asn.1/Elementary Procedure Definitions.asn1"
 * 	`asn1c -pdu=all -fcompound-names -fno-include-deps -findirect-choice -gen-PER -D src`
 */

#include "Ngap_SuccessfulOutcome.h"

static const long asn_VAL_1_Ngap_id_AMFConfigurationUpdate = 0;
static const long asn_VAL_1_Ngap_reject = 0;
static const long asn_VAL_2_Ngap_id_HandoverCancel = 10;
static const long asn_VAL_2_Ngap_reject = 0;
static const long asn_VAL_3_Ngap_id_HandoverPreparation = 12;
static const long asn_VAL_3_Ngap_reject = 0;
static const long asn_VAL_4_Ngap_id_HandoverResourceAllocation = 13;
static const long asn_VAL_4_Ngap_reject = 0;
static const long asn_VAL_5_Ngap_id_InitialContextSetup = 14;
static const long asn_VAL_5_Ngap_reject = 0;
static const long asn_VAL_6_Ngap_id_NGReset = 20;
static const long asn_VAL_6_Ngap_reject = 0;
static const long asn_VAL_7_Ngap_id_NGSetup = 21;
static const long asn_VAL_7_Ngap_reject = 0;
static const long asn_VAL_8_Ngap_id_PathSwitchRequest = 25;
static const long asn_VAL_8_Ngap_reject = 0;
static const long asn_VAL_9_Ngap_id_PDUSessionResourceModify = 26;
static const long asn_VAL_9_Ngap_reject = 0;
static const long asn_VAL_10_Ngap_id_PDUSessionResourceModifyIndication = 27;
static const long asn_VAL_10_Ngap_reject = 0;
static const long asn_VAL_11_Ngap_id_PDUSessionResourceRelease = 28;
static const long asn_VAL_11_Ngap_reject = 0;
static const long asn_VAL_12_Ngap_id_PDUSessionResourceSetup = 29;
static const long asn_VAL_12_Ngap_reject = 0;
static const long asn_VAL_13_Ngap_id_PWSCancel = 32;
static const long asn_VAL_13_Ngap_reject = 0;
static const long asn_VAL_14_Ngap_id_RANConfigurationUpdate = 35;
static const long asn_VAL_14_Ngap_reject = 0;
static const long asn_VAL_15_Ngap_id_UEContextModification = 40;
static const long asn_VAL_15_Ngap_reject = 0;
static const long asn_VAL_16_Ngap_id_UEContextRelease = 41;
static const long asn_VAL_16_Ngap_reject = 0;
static const long asn_VAL_17_Ngap_id_UERadioCapabilityCheck = 43;
static const long asn_VAL_17_Ngap_reject = 0;
static const long asn_VAL_18_Ngap_id_WriteReplaceWarning = 51;
static const long asn_VAL_18_Ngap_reject = 0;
static const long asn_VAL_19_Ngap_id_AMFStatusIndication = 1;
static const long asn_VAL_19_Ngap_ignore = 1;
static const long asn_VAL_20_Ngap_id_CellTrafficTrace = 2;
static const long asn_VAL_20_Ngap_ignore = 1;
static const long asn_VAL_21_Ngap_id_DeactivateTrace = 3;
static const long asn_VAL_21_Ngap_ignore = 1;
static const long asn_VAL_22_Ngap_id_DownlinkNASTransport = 4;
static const long asn_VAL_22_Ngap_ignore = 1;
static const long asn_VAL_23_Ngap_id_DownlinkNonUEAssociatedNRPPaTransport = 5;
static const long asn_VAL_23_Ngap_ignore = 1;
static const long asn_VAL_24_Ngap_id_DownlinkRANConfigurationTransfer = 6;
static const long asn_VAL_24_Ngap_ignore = 1;
static const long asn_VAL_25_Ngap_id_DownlinkRANStatusTransfer = 7;
static const long asn_VAL_25_Ngap_ignore = 1;
static const long asn_VAL_26_Ngap_id_DownlinkUEAssociatedNRPPaTransport = 8;
static const long asn_VAL_26_Ngap_ignore = 1;
static const long asn_VAL_27_Ngap_id_ErrorIndication = 9;
static const long asn_VAL_27_Ngap_ignore = 1;
static const long asn_VAL_28_Ngap_id_HandoverNotification = 11;
static const long asn_VAL_28_Ngap_ignore = 1;
static const long asn_VAL_29_Ngap_id_InitialUEMessage = 15;
static const long asn_VAL_29_Ngap_ignore = 1;
static const long asn_VAL_30_Ngap_id_LocationReport = 18;
static const long asn_VAL_30_Ngap_ignore = 1;
static const long asn_VAL_31_Ngap_id_LocationReportingControl = 16;
static const long asn_VAL_31_Ngap_ignore = 1;
static const long asn_VAL_32_Ngap_id_LocationReportingFailureIndication = 17;
static const long asn_VAL_32_Ngap_ignore = 1;
static const long asn_VAL_33_Ngap_id_NASNonDeliveryIndication = 19;
static const long asn_VAL_33_Ngap_ignore = 1;
static const long asn_VAL_34_Ngap_id_OverloadStart = 22;
static const long asn_VAL_34_Ngap_ignore = 1;
static const long asn_VAL_35_Ngap_id_OverloadStop = 23;
static const long asn_VAL_35_Ngap_reject = 0;
static const long asn_VAL_36_Ngap_id_Paging = 24;
static const long asn_VAL_36_Ngap_ignore = 1;
static const long asn_VAL_37_Ngap_id_PDUSessionResourceNotify = 30;
static const long asn_VAL_37_Ngap_ignore = 1;
static const long asn_VAL_38_Ngap_id_PrivateMessage = 31;
static const long asn_VAL_38_Ngap_ignore = 1;
static const long asn_VAL_39_Ngap_id_PWSFailureIndication = 33;
static const long asn_VAL_39_Ngap_ignore = 1;
static const long asn_VAL_40_Ngap_id_PWSRestartIndication = 34;
static const long asn_VAL_40_Ngap_ignore = 1;
static const long asn_VAL_41_Ngap_id_RerouteNASRequest = 36;
static const long asn_VAL_41_Ngap_reject = 0;
static const long asn_VAL_42_Ngap_id_RRCInactiveTransitionReport = 37;
static const long asn_VAL_42_Ngap_ignore = 1;
static const long asn_VAL_43_Ngap_id_TraceFailureIndication = 38;
static const long asn_VAL_43_Ngap_ignore = 1;
static const long asn_VAL_44_Ngap_id_TraceStart = 39;
static const long asn_VAL_44_Ngap_ignore = 1;
static const long asn_VAL_45_Ngap_id_UEContextReleaseRequest = 42;
static const long asn_VAL_45_Ngap_ignore = 1;
static const long asn_VAL_46_Ngap_id_UERadioCapabilityInfoIndication = 44;
static const long asn_VAL_46_Ngap_ignore = 1;
static const long asn_VAL_47_Ngap_id_UETNLABindingRelease = 45;
static const long asn_VAL_47_Ngap_ignore = 1;
static const long asn_VAL_48_Ngap_id_UplinkNASTransport = 46;
static const long asn_VAL_48_Ngap_ignore = 1;
static const long asn_VAL_49_Ngap_id_UplinkNonUEAssociatedNRPPaTransport = 47;
static const long asn_VAL_49_Ngap_ignore = 1;
static const long asn_VAL_50_Ngap_id_UplinkRANConfigurationTransfer = 48;
static const long asn_VAL_50_Ngap_ignore = 1;
static const long asn_VAL_51_Ngap_id_UplinkRANStatusTransfer = 49;
static const long asn_VAL_51_Ngap_ignore = 1;
static const long asn_VAL_52_Ngap_id_UplinkUEAssociatedNRPPaTransport = 50;
static const long asn_VAL_52_Ngap_ignore = 1;
static const asn_ioc_cell_t asn_IOS_Ngap_NGAP_ELEMENTARY_PROCEDURES_1_rows[] = {
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_AMFConfigurationUpdate },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_AMFConfigurationUpdateAcknowledge },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_AMFConfigurationUpdateFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_1_Ngap_id_AMFConfigurationUpdate },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_1_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_HandoverCancel },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_HandoverCancelAcknowledge },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_2_Ngap_id_HandoverCancel },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_2_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_HandoverRequired },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_HandoverCommand },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_HandoverPreparationFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_3_Ngap_id_HandoverPreparation },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_3_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_HandoverRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_HandoverRequestAcknowledge },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_HandoverFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_4_Ngap_id_HandoverResourceAllocation },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_4_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_InitialContextSetupRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_InitialContextSetupResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_InitialContextSetupFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_5_Ngap_id_InitialContextSetup },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_5_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_NGReset },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_NGResetAcknowledge },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_6_Ngap_id_NGReset },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_6_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_NGSetupRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_NGSetupResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_NGSetupFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_7_Ngap_id_NGSetup },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_7_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PathSwitchRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PathSwitchRequestAcknowledge },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PathSwitchRequestFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_8_Ngap_id_PathSwitchRequest },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_8_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PDUSessionResourceModifyRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PDUSessionResourceModifyResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_9_Ngap_id_PDUSessionResourceModify },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_9_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PDUSessionResourceModifyIndication },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PDUSessionResourceModifyConfirm },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_10_Ngap_id_PDUSessionResourceModifyIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_10_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PDUSessionResourceReleaseCommand },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PDUSessionResourceReleaseResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_11_Ngap_id_PDUSessionResourceRelease },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_11_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PDUSessionResourceSetupRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PDUSessionResourceSetupResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_12_Ngap_id_PDUSessionResourceSetup },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_12_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PWSCancelRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_PWSCancelResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_13_Ngap_id_PWSCancel },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_13_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_RANConfigurationUpdate },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_RANConfigurationUpdateAcknowledge },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_RANConfigurationUpdateFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_14_Ngap_id_RANConfigurationUpdate },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_14_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UEContextModificationRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_UEContextModificationResponse },
	{ "&UnsuccessfulOutcome", aioc__type, &asn_DEF_Ngap_UEContextModificationFailure },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_15_Ngap_id_UEContextModification },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_15_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UEContextReleaseCommand },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_UEContextReleaseComplete },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_16_Ngap_id_UEContextRelease },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_16_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UERadioCapabilityCheckRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_UERadioCapabilityCheckResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_17_Ngap_id_UERadioCapabilityCheck },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_17_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_WriteReplaceWarningRequest },
	{ "&SuccessfulOutcome", aioc__type, &asn_DEF_Ngap_WriteReplaceWarningResponse },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_18_Ngap_id_WriteReplaceWarning },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_18_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_AMFStatusIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_19_Ngap_id_AMFStatusIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_19_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_CellTrafficTrace },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_20_Ngap_id_CellTrafficTrace },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_20_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_DeactivateTrace },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_21_Ngap_id_DeactivateTrace },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_21_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_DownlinkNASTransport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_22_Ngap_id_DownlinkNASTransport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_22_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_DownlinkNonUEAssociatedNRPPaTransport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_23_Ngap_id_DownlinkNonUEAssociatedNRPPaTransport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_23_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_DownlinkRANConfigurationTransfer },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_24_Ngap_id_DownlinkRANConfigurationTransfer },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_24_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_DownlinkRANStatusTransfer },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_25_Ngap_id_DownlinkRANStatusTransfer },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_25_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_DownlinkUEAssociatedNRPPaTransport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_26_Ngap_id_DownlinkUEAssociatedNRPPaTransport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_26_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_ErrorIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_27_Ngap_id_ErrorIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_27_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_HandoverNotify },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_28_Ngap_id_HandoverNotification },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_28_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_InitialUEMessage },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_29_Ngap_id_InitialUEMessage },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_29_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_LocationReport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_30_Ngap_id_LocationReport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_30_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_LocationReportingControl },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_31_Ngap_id_LocationReportingControl },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_31_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_LocationReportingFailureIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_32_Ngap_id_LocationReportingFailureIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_32_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_NASNonDeliveryIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_33_Ngap_id_NASNonDeliveryIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_33_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_OverloadStart },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_34_Ngap_id_OverloadStart },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_34_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_OverloadStop },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_35_Ngap_id_OverloadStop },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_35_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_Paging },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_36_Ngap_id_Paging },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_36_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PDUSessionResourceNotify },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_37_Ngap_id_PDUSessionResourceNotify },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_37_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PrivateMessage },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_38_Ngap_id_PrivateMessage },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_38_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PWSFailureIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_39_Ngap_id_PWSFailureIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_39_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_PWSRestartIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_40_Ngap_id_PWSRestartIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_40_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_RerouteNASRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_41_Ngap_id_RerouteNASRequest },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_41_Ngap_reject },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_RRCInactiveTransitionReport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_42_Ngap_id_RRCInactiveTransitionReport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_42_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_TraceFailureIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_43_Ngap_id_TraceFailureIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_43_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_TraceStart },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_44_Ngap_id_TraceStart },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_44_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UEContextReleaseRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_45_Ngap_id_UEContextReleaseRequest },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_45_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UERadioCapabilityInfoIndication },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_46_Ngap_id_UERadioCapabilityInfoIndication },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_46_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UETNLABindingReleaseRequest },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_47_Ngap_id_UETNLABindingRelease },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_47_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UplinkNASTransport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_48_Ngap_id_UplinkNASTransport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_48_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UplinkNonUEAssociatedNRPPaTransport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_49_Ngap_id_UplinkNonUEAssociatedNRPPaTransport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_49_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UplinkRANConfigurationTransfer },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_50_Ngap_id_UplinkRANConfigurationTransfer },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_50_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UplinkRANStatusTransfer },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_51_Ngap_id_UplinkRANStatusTransfer },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_51_Ngap_ignore },
	{ "&InitiatingMessage", aioc__type, &asn_DEF_Ngap_UplinkUEAssociatedNRPPaTransport },
	{ "&SuccessfulOutcome",  },
	{ "&UnsuccessfulOutcome",  },
	{ "&procedureCode", aioc__value, &asn_DEF_Ngap_ProcedureCode, &asn_VAL_52_Ngap_id_UplinkUEAssociatedNRPPaTransport },
	{ "&criticality", aioc__value, &asn_DEF_Ngap_Criticality, &asn_VAL_52_Ngap_ignore }
};
static const asn_ioc_set_t asn_IOS_Ngap_NGAP_ELEMENTARY_PROCEDURES_1[] = {
	{ 52, 5, asn_IOS_Ngap_NGAP_ELEMENTARY_PROCEDURES_1_rows }
};
static int
memb_Ngap_procedureCode_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	long value;
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	value = *(const long *)sptr;
	
	if((value >= 0 && value <= 255)) {
		/* Constraint check succeeded */
		return 0;
	} else {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: constraint failed (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
}

static asn_type_selector_result_t
select_SuccessfulOutcome_Ngap_criticality_type(const asn_TYPE_descriptor_t *parent_type, const void *parent_sptr) {
	asn_type_selector_result_t result = {0, 0};
	const asn_ioc_set_t *itable = asn_IOS_Ngap_NGAP_ELEMENTARY_PROCEDURES_1;
	size_t constraining_column = 3; /* &procedureCode */
	size_t for_column = 4; /* &criticality */
	size_t row, presence_index = 0;
	const long *constraining_value = (const long *)((const char *)parent_sptr + offsetof(struct Ngap_SuccessfulOutcome, procedureCode));
	
	for(row=0; row < itable->rows_count; row++) {
	    const asn_ioc_cell_t *constraining_cell = &itable->rows[row * itable->columns_count + constraining_column];
	    const asn_ioc_cell_t *type_cell = &itable->rows[row * itable->columns_count + for_column];
	
	    if(type_cell->cell_kind == aioc__undefined)
	        continue;
	
	    presence_index++;
	    if(constraining_cell->type_descriptor->op->compare_struct(constraining_cell->type_descriptor, constraining_value, constraining_cell->value_sptr) == 0) {
	        result.type_descriptor = type_cell->type_descriptor;
	        result.presence_index = presence_index;
	        break;
	    }
	}
	
	return result;
}

static int
memb_Ngap_criticality_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

static asn_type_selector_result_t
select_SuccessfulOutcome_Ngap_value_type(const asn_TYPE_descriptor_t *parent_type, const void *parent_sptr) {
	asn_type_selector_result_t result = {0, 0};
	const asn_ioc_set_t *itable = asn_IOS_Ngap_NGAP_ELEMENTARY_PROCEDURES_1;
	size_t constraining_column = 3; /* &procedureCode */
	size_t for_column = 1; /* &SuccessfulOutcome */
	size_t row, presence_index = 0;
	const long *constraining_value = (const long *)((const char *)parent_sptr + offsetof(struct Ngap_SuccessfulOutcome, procedureCode));
	
	for(row=0; row < itable->rows_count; row++) {
	    const asn_ioc_cell_t *constraining_cell = &itable->rows[row * itable->columns_count + constraining_column];
	    const asn_ioc_cell_t *type_cell = &itable->rows[row * itable->columns_count + for_column];
	
	    if(type_cell->cell_kind == aioc__undefined)
	        continue;
	
	    presence_index++;
	    if(constraining_cell->type_descriptor->op->compare_struct(constraining_cell->type_descriptor, constraining_value, constraining_cell->value_sptr) == 0) {
	        result.type_descriptor = type_cell->type_descriptor;
	        result.presence_index = presence_index;
	        break;
	    }
	}
	
	return result;
}

static int
memb_Ngap_value_constraint_1(const asn_TYPE_descriptor_t *td, const void *sptr,
			asn_app_constraint_failed_f *ctfailcb, void *app_key) {
	
	if(!sptr) {
		ASN__CTFAIL(app_key, td, sptr,
			"%s: value not given (%s:%d)",
			td->name, __FILE__, __LINE__);
		return -1;
	}
	
	
	if(1 /* No applicable constraints whatsoever */) {
		/* Nothing is here. See below */
	}
	
	return td->encoding_constraints.general_constraints(td, sptr, ctfailcb, app_key);
}

static asn_oer_constraints_t asn_OER_memb_Ngap_procedureCode_constr_2 CC_NOTUSED = {
	{ 1, 1 }	/* (0..255) */,
	-1};
static asn_per_constraints_t asn_PER_memb_Ngap_procedureCode_constr_2 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 8,  8,  0,  255 }	/* (0..255) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_Ngap_criticality_constr_3 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_memb_Ngap_criticality_constr_3 CC_NOTUSED = {
	{ APC_CONSTRAINED,	 2,  2,  0,  2 }	/* (0..2) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_oer_constraints_t asn_OER_memb_Ngap_value_constr_4 CC_NOTUSED = {
	{ 0, 0 },
	-1};
static asn_per_constraints_t asn_PER_memb_Ngap_value_constr_4 CC_NOTUSED = {
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
static asn_TYPE_member_t asn_MBR_Ngap_value_4[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.AMFConfigurationUpdateAcknowledge),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_AMFConfigurationUpdateAcknowledge,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"AMFConfigurationUpdateAcknowledge"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.HandoverCancelAcknowledge),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_HandoverCancelAcknowledge,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"HandoverCancelAcknowledge"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.HandoverCommand),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_HandoverCommand,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"HandoverCommand"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.HandoverRequestAcknowledge),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_HandoverRequestAcknowledge,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"HandoverRequestAcknowledge"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.InitialContextSetupResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_InitialContextSetupResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"InitialContextSetupResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.NGResetAcknowledge),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_NGResetAcknowledge,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"NGResetAcknowledge"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.NGSetupResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_NGSetupResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"NGSetupResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.PathSwitchRequestAcknowledge),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_PathSwitchRequestAcknowledge,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"PathSwitchRequestAcknowledge"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.PDUSessionResourceModifyResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_PDUSessionResourceModifyResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"PDUSessionResourceModifyResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.PDUSessionResourceModifyConfirm),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_PDUSessionResourceModifyConfirm,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"PDUSessionResourceModifyConfirm"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.PDUSessionResourceReleaseResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_PDUSessionResourceReleaseResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"PDUSessionResourceReleaseResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.PDUSessionResourceSetupResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_PDUSessionResourceSetupResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"PDUSessionResourceSetupResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.PWSCancelResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_PWSCancelResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"PWSCancelResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.RANConfigurationUpdateAcknowledge),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_RANConfigurationUpdateAcknowledge,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"RANConfigurationUpdateAcknowledge"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.UEContextModificationResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_UEContextModificationResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"UEContextModificationResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.UEContextReleaseComplete),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_UEContextReleaseComplete,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"UEContextReleaseComplete"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.UERadioCapabilityCheckResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_UERadioCapabilityCheckResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"UERadioCapabilityCheckResponse"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome__value, choice.WriteReplaceWarningResponse),
		(ASN_TAG_CLASS_UNIVERSAL | (16 << 2)),
		0,
		&asn_DEF_Ngap_WriteReplaceWarningResponse,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"WriteReplaceWarningResponse"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_Ngap_value_tag2el_4[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 0, 0, 17 }, /* AMFConfigurationUpdateAcknowledge */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 1, -1, 16 }, /* HandoverCancelAcknowledge */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 2, -2, 15 }, /* HandoverCommand */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 3, -3, 14 }, /* HandoverRequestAcknowledge */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 4, -4, 13 }, /* InitialContextSetupResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 5, -5, 12 }, /* NGResetAcknowledge */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 6, -6, 11 }, /* NGSetupResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 7, -7, 10 }, /* PathSwitchRequestAcknowledge */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 8, -8, 9 }, /* PDUSessionResourceModifyResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 9, -9, 8 }, /* PDUSessionResourceModifyConfirm */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 10, -10, 7 }, /* PDUSessionResourceReleaseResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 11, -11, 6 }, /* PDUSessionResourceSetupResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 12, -12, 5 }, /* PWSCancelResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 13, -13, 4 }, /* RANConfigurationUpdateAcknowledge */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 14, -14, 3 }, /* UEContextModificationResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 15, -15, 2 }, /* UEContextReleaseComplete */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 16, -16, 1 }, /* UERadioCapabilityCheckResponse */
    { (ASN_TAG_CLASS_UNIVERSAL | (16 << 2)), 17, -17, 0 } /* WriteReplaceWarningResponse */
};
static asn_CHOICE_specifics_t asn_SPC_Ngap_value_specs_4 = {
	sizeof(struct Ngap_SuccessfulOutcome__value),
	offsetof(struct Ngap_SuccessfulOutcome__value, _asn_ctx),
	offsetof(struct Ngap_SuccessfulOutcome__value, present),
	sizeof(((struct Ngap_SuccessfulOutcome__value *)0)->present),
	asn_MAP_Ngap_value_tag2el_4,
	18,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
static /* Use -fall-defs-global to expose */
asn_TYPE_descriptor_t asn_DEF_Ngap_value_4 = {
	"value",
	"value",
	&asn_OP_OPEN_TYPE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{ 0, 0, OPEN_TYPE_constraint },
	asn_MBR_Ngap_value_4,
	18,	/* Elements count */
	&asn_SPC_Ngap_value_specs_4	/* Additional specs */
};

asn_TYPE_member_t asn_MBR_Ngap_SuccessfulOutcome_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome, procedureCode),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_ProcedureCode,
		0,
		{ &asn_OER_memb_Ngap_procedureCode_constr_2, &asn_PER_memb_Ngap_procedureCode_constr_2,  memb_Ngap_procedureCode_constraint_1 },
		0, 0, /* No default value */
		"procedureCode"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome, criticality),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_Criticality,
		select_SuccessfulOutcome_Ngap_criticality_type,
		{ &asn_OER_memb_Ngap_criticality_constr_3, &asn_PER_memb_Ngap_criticality_constr_3,  memb_Ngap_criticality_constraint_1 },
		0, 0, /* No default value */
		"criticality"
		},
	{ ATF_OPEN_TYPE | ATF_NOFLAGS, 0, offsetof(struct Ngap_SuccessfulOutcome, value),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Ngap_value_4,
		select_SuccessfulOutcome_Ngap_value_type,
		{ &asn_OER_memb_Ngap_value_constr_4, &asn_PER_memb_Ngap_value_constr_4,  memb_Ngap_value_constraint_1 },
		0, 0, /* No default value */
		"value"
		},
};
static const ber_tlv_tag_t asn_DEF_Ngap_SuccessfulOutcome_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Ngap_SuccessfulOutcome_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* procedureCode */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* criticality */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* value */
};
asn_SEQUENCE_specifics_t asn_SPC_Ngap_SuccessfulOutcome_specs_1 = {
	sizeof(struct Ngap_SuccessfulOutcome),
	offsetof(struct Ngap_SuccessfulOutcome, _asn_ctx),
	asn_MAP_Ngap_SuccessfulOutcome_tag2el_1,
	3,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Ngap_SuccessfulOutcome = {
	"SuccessfulOutcome",
	"SuccessfulOutcome",
	&asn_OP_SEQUENCE,
	asn_DEF_Ngap_SuccessfulOutcome_tags_1,
	sizeof(asn_DEF_Ngap_SuccessfulOutcome_tags_1)
		/sizeof(asn_DEF_Ngap_SuccessfulOutcome_tags_1[0]), /* 1 */
	asn_DEF_Ngap_SuccessfulOutcome_tags_1,	/* Same as above */
	sizeof(asn_DEF_Ngap_SuccessfulOutcome_tags_1)
		/sizeof(asn_DEF_Ngap_SuccessfulOutcome_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Ngap_SuccessfulOutcome_1,
	3,	/* Elements count */
	&asn_SPC_Ngap_SuccessfulOutcome_specs_1	/* Additional specs */
};

