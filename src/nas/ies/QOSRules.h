#ifndef _QOSRULES_H_
#define _QOSRULES_H_

#include <stdint.h>
#include "bstrlib.h"
#include "OCTET_STRING.h"

#define QOS_RULES_MINIMUM_LENGTH 7
#define QOS_RULES_MAXIMUM_LENGTH 65538

//Rule operation code (bits 8 to 6 of octet 7)
#define CREATE_NEW_QOS_RULE											0b001
#define DELETE_EXISTING_QOS_RULE									0b010
#define MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS				0b011
#define MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS		0b100
#define MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS			0b101
#define MODIFY_EXISTING_QOS_RULE_WITHOUT_MODIFYING_PACKET_FILTERS	0b110

//Segregation bit (bit 7 of octet m+2)
#define SEGREGATION_NOT_REQUESTED	0
#define SEGREGATION_REQUESTED		1

//DQR bit (bit 5 of octet 7)
#define THE_QOS_RULE_IS_NOT_THE_DEFAULT_QOS_RULE	0
#define THE_QOS_RULE_IS_DEFAULT_QOS_RULE			1

typedef struct{
	uint8_t packetfilteridentifier:4;
}ModifyAndDelete;

typedef struct{
	uint8_t component_type;
	bstring component_value;
}PacketFilterContents;
typedef struct{
	uint8_t packetfilterdirection:2;
	uint8_t packetfilteridentifier:4;
	//uint8_t lenghtofpacketfiltercontents;
	PacketFilterContents packetfiltercontents;
	
}Create_ModifyAndAdd_ModifyAndReplace;

typedef struct{
	uint8_t qosruleidentifer;
	//uint16_t LengthofQoSrule;
	uint8_t ruleoperationcode:3;
	uint8_t dqrbit:1;
	uint8_t numberofpacketfilters:4;
	union {
		ModifyAndDelete *modifyanddelete;
		Create_ModifyAndAdd_ModifyAndReplace *create_modifyandadd_modifyandreplace;
	}packetfilterlist;
	//uint16_t packetfilterlistnumber;
	uint8_t qosruleprecedence;
	uint8_t segregation:1;
	uint8_t qosflowidentifer:6;
}QOSRulesIE;

typedef struct{
	uint16_t lengthofqosrulesie;
	QOSRulesIE *qosrulesie;
}QOSRules;

int encode_qos_rules ( QOSRules qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_qos_rules ( QOSRules * qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

#endif                                                                                                                                 