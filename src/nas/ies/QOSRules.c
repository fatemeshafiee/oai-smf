#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#include "TLVEncoder.h"
#include "TLVDecoder.h"
#include "QOSRules.h"

int encode_qos_rules ( QOSRules qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	#if 0
	uint8_t *lenPtr = NULL;
	uint8_t *lenqosrule = NULL;
	uint8_t lenmoment = 0;
	uint8_t bitstream = 0;
	uint16_t lenqosrule_16 = 0;
    uint32_t encoded = 0;
    int encode_result = 0;
	int i = 0,j = 0;
	
    CHECK_PDU_POINTER_AND_LENGTH_ENCODER (buffer,QOS_RULES_MINIMUM_LENGTH , len);
    

	if( iei > 0 )
	{
		*buffer=iei;
		encoded++;
	}
	
    lenPtr = (buffer + encoded);
    encoded++;
    encoded++;

	for(i=0;i<qosrules.numberofqosrulesie;i++)
	{
		ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].qosruleidentifer,encoded);
		
		lenqosrule = buffer + encoded;
		encoded++;
    	encoded++;
		lenmoment = encoded;

		bitstream = (uint8_t)(qosrules.qosrulesie[i].ruleoperationcode << 5);
		bitstream |= (uint8_t)(qosrules.qosrulesie[i].dqrbit << 4);
		bitstream |= (uint8_t)qosrules.qosrulesie[i].numberofpacketfilters;
		ENCODE_U8(buffer+encoded,bitstream,encoded);

		if((bitstream >> 5) == MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS)
		{
			for(j = 0;j < (bitstream & 0x0f);j++)
			{
				ENCODE_U8(buffer+encoded,(uint8_t)qosrules.qosrulesie[i].packetfilterlist.packetfilterdelete[j].packetfilteridentifier,encoded);
			}
			ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].qosruleprecedence,encoded);
			ENCODE_U8(buffer+encoded,(uint8_t)((qosrules.qosrulesie[i].segregation<<6) | (qosrules.qosrulesie[i].qosflowidentifer & 0x3f)),encoded);
		}
		else if(((bitstream >> 5) == CREATE_NEW_QOS_RULE) || ((bitstream >> 5) == MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS) || ((bitstream >> 5) == MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS))
		{
			for(j = 0;j < (bitstream & 0x0f);j++)
			{
				ENCODE_U8(buffer+encoded,(uint8_t)((qosrules.qosrulesie[i].packetfilterlist.packetfilternodelete[j].packetfilterdirection << 4)|(qosrules.qosrulesie[i].packetfilterlist.packetfilternodelete[j].packetfilteridentifier & 0x0f)),encoded);

				uint8_t *lenghtofpacketfiltercontents = buffer + encoded;
				encoded++;
				
				if ((encode_result = encode_bstring (qosrules.qosrulesie[i].packetfilterlist.packetfilternodelete[j].packetfiltercontents, buffer + encoded, len - encoded)) < 0)
        			return encode_result;
    			else
        			encoded += encode_result;
				*lenghtofpacketfiltercontents = encode_result;
			}
			ENCODE_U8(buffer+encoded,qosrules.qosrulesie[i].qosruleprecedence,encoded);
			ENCODE_U8(buffer+encoded,(uint8_t)((qosrules.qosrulesie[i].segregation<<6) | (qosrules.qosrulesie[i].qosflowidentifer & 0x3f)),encoded);
		}
		lenqosrule_16 = encoded - lenmoment;
		*lenqosrule = lenqosrule_16/(1<<8);
		lenqosrule++;
		*lenqosrule = lenqosrule_16%(1<<8);
	}

    uint32_t res = encoded - 2 - ((iei > 0) ? 1 : 0);
    *lenPtr =res/(1<<8);
    lenPtr++;
    *lenPtr = res%(1<<8);

    return encoded;
	#endif
	return 0;
}

int decode_qos_rules ( QOSRules * qosrules, uint8_t iei, uint8_t * buffer, uint32_t len  ) 
{
	#if 0
	int decoded=0;
	uint16_t ielen=0;
	int decode_result = 0;
	uint16_t allsize = 0;
	uint8_t *buffer_tmp = NULL;
	uint16_t numberofqosrulesie = 0;
	uint16_t lenqosrule = 0;
	uint8_t bitstream = 0;
	int i=0,j=0;
	

    if (iei > 0)
    {
        CHECK_IEI_DECODER (iei, *buffer);
        decoded++;
    }


    ielen = *(buffer + decoded);
    decoded++;
    ielen = ( ielen << 8)+*(buffer + decoded);
    decoded++;
    CHECK_LENGTH_DECODER (len - decoded, ielen);

	//qosrules->qosrulesie = (QOSRulesIE *)malloc(ielen);
	buffer_tmp = buffer + decoded;
	//allsize = ielen;
	while(allsize < ielen)
	{
		allsize = *(buffer_tmp+1)+1;
		buffer_tmp += allsize;
		numberofqosrulesie++;
	}

	qosrules->numberofqosrulesie = numberofqosrulesie;
	qosrules->qosrulesie = (QOSRulesIE *)calloc(qosrules->numberofqosrulesie,sizeof(QOSRulesIE));
	for(i=0;i<numberofqosrulesie;i++)
	{
		DECODE_U8(buffer+decoded,qosrules->qosrulesie[i].qosruleidentifer,decoded);

		decoded++;
		decoded++;
		/*lenqosrule = *(buffer + decoded);
		decoded++;
		lenqosrule = (lenqosrule << 8)+*(buffer + decoded);
    	decoded++;
		lenmoment = encoded;
*/		
		DECODE_U8(buffer+decoded,bitstream,decoded);
		qosrules->qosrulesie[i].ruleoperationcode = (bitstream>>5);
		qosrules->qosrulesie[i].dqrbit = (bitstream>>4)&0x01;
		qosrules->qosrulesie[i].numberofpacketfilters = bitstream&0x0f;

		if(qosrules->qosrulesie[i].ruleoperationcode == MODIFY_EXISTING_QOS_RULE_AND_DELETE_PACKET_FILTERS)
		{
			qosrules->qosrulesie[i].packetfilterlist.packetfilterdelete = (PacketFilterDelete *)calloc(qosrules->qosrulesie[i].numberofpacketfilters,sizeof(PacketFilterDelete));
			for(j = 0;j < qosrules->qosrulesie[i].numberofpacketfilters;j++)
			{
				DECODE_U8(buffer+decoded,bitstream,decoded);
				qosrules->qosrulesie[i].packetfilterlist.packetfilterdelete[j].packetfilteridentifier = bitstream&0x0f;
			}
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].qosruleprecedence = bitstream;
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].segregation = (bitstream>>6)&0x01;
			qosrules->qosrulesie[i].qosflowidentifer = bitstream&0x3f;
		}
		else if((qosrules->qosrulesie[i].ruleoperationcode == CREATE_NEW_QOS_RULE) || (qosrules->qosrulesie[i].ruleoperationcode == MODIFY_EXISTING_QOS_RULE_AND_ADD_PACKET_FILTERS) || (qosrules->qosrulesie[i].ruleoperationcode == MODIFY_EXISTING_QOS_RULE_AND_REPLACE_ALL_PACKET_FILTERS))
		{
			qosrules->qosrulesie[i].packetfilterlist.packetfilternodelete = (PacketFilterNoDelete *)calloc(qosrules->qosrulesie[i].numberofpacketfilters,sizeof(PacketFilterNoDelete));
			for(j = 0;j < qosrules->qosrulesie[i].numberofpacketfilters;j++)
			{
				DECODE_U8(buffer+decoded,bitstream,decoded);
				qosrules->qosrulesie[i].packetfilterlist.packetfilternodelete[j].packetfilterdirection = (bitstream>>4)&0x03;
				qosrules->qosrulesie[i].packetfilterlist.packetfilternodelete[j].packetfilteridentifier = bitstream&0x0f;
				
				uint8_t *lenghtofpacketfiltercontents = *(buffer + decoded);
				decoded++;
				
				if ((decode_result = decode_bstring (qosrules->qosrulesie[i].packetfilterlist.packetfilternodelete[j].packetfiltercontents, lenghtofpacketfiltercontents, buffer + decoded, len - decoded)) < 0)
        			return decode_result;
    			else
        			decoded += decode_result;
			}
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].qosruleprecedence = bitstream;
			DECODE_U8(buffer+decoded,bitstream,decoded);
			qosrules->qosrulesie[i].segregation = (bitstream>>6)&0x01;
			qosrules->qosrulesie[i].qosflowidentifer = bitstream&0x3f;
		}
	}

	return decoded;
	#endif
	return 0;
}

