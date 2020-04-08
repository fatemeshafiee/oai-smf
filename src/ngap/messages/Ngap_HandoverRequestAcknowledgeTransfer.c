/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "asn.1/Information Element Definitions.asn1"
 * 	`asn1c -pdu=all -fcompound-names -fno-include-deps -findirect-choice -gen-PER -D src`
 */

#include "Ngap_HandoverRequestAcknowledgeTransfer.h"

#include "Ngap_UPTransportLayerInformation.h"
#include "Ngap_SecurityResult.h"
#include "Ngap_QosFlowListWithCause.h"
#include "Ngap_DataForwardingResponseDRBList.h"
#include "Ngap_ProtocolExtensionContainer.h"
static asn_TYPE_member_t asn_MBR_Ngap_HandoverRequestAcknowledgeTransfer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, dL_NGU_UP_TNLInformation),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Ngap_UPTransportLayerInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dL-NGU-UP-TNLInformation"
		},
	{ ATF_POINTER, 2, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, dLForwardingUP_TNLInformation),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Ngap_UPTransportLayerInformation,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dLForwardingUP-TNLInformation"
		},
	{ ATF_POINTER, 1, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, securityResult),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_SecurityResult,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"securityResult"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, qosFlowSetupResponseList),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_QosFlowListWithDataForwarding,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"qosFlowSetupResponseList"
		},
	{ ATF_POINTER, 3, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, qosFlowFailedToSetupList),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_QosFlowListWithCause,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"qosFlowFailedToSetupList"
		},
	{ ATF_POINTER, 2, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, dataForwardingResponseDRBList),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_DataForwardingResponseDRBList,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"dataForwardingResponseDRBList"
		},
	{ ATF_POINTER, 1, offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, iE_Extensions),
		(ASN_TAG_CLASS_CONTEXT | (6 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Ngap_ProtocolExtensionContainer_175P63,
		0,
		{ 0, 0, 0 },
		0, 0, /* No default value */
		"iE-Extensions"
		},
};
static const int asn_MAP_Ngap_HandoverRequestAcknowledgeTransfer_oms_1[] = { 1, 2, 4, 5, 6 };
static const ber_tlv_tag_t asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Ngap_HandoverRequestAcknowledgeTransfer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* dL-NGU-UP-TNLInformation */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* dLForwardingUP-TNLInformation */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* securityResult */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* qosFlowSetupResponseList */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* qosFlowFailedToSetupList */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 }, /* dataForwardingResponseDRBList */
    { (ASN_TAG_CLASS_CONTEXT | (6 << 2)), 6, 0, 0 } /* iE-Extensions */
};
static asn_SEQUENCE_specifics_t asn_SPC_Ngap_HandoverRequestAcknowledgeTransfer_specs_1 = {
	sizeof(struct Ngap_HandoverRequestAcknowledgeTransfer),
	offsetof(struct Ngap_HandoverRequestAcknowledgeTransfer, _asn_ctx),
	asn_MAP_Ngap_HandoverRequestAcknowledgeTransfer_tag2el_1,
	7,	/* Count of tags in the map */
	asn_MAP_Ngap_HandoverRequestAcknowledgeTransfer_oms_1,	/* Optional members */
	5, 0,	/* Root/Additions */
	7,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer = {
	"HandoverRequestAcknowledgeTransfer",
	"HandoverRequestAcknowledgeTransfer",
	&asn_OP_SEQUENCE,
	asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1,
	sizeof(asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1)
		/sizeof(asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1[0]), /* 1 */
	asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1,	/* Same as above */
	sizeof(asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1)
		/sizeof(asn_DEF_Ngap_HandoverRequestAcknowledgeTransfer_tags_1[0]), /* 1 */
	{ 0, 0, SEQUENCE_constraint },
	asn_MBR_Ngap_HandoverRequestAcknowledgeTransfer_1,
	7,	/* Elements count */
	&asn_SPC_Ngap_HandoverRequestAcknowledgeTransfer_specs_1	/* Additional specs */
};

