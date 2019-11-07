#include <stdint.h>
    
#include "ngap_common.h"
#include "dynamic_memory_check.h"


int  check_NGAP_pdu_constraints(Ngap_NGAP_PDU_t *pdu)
{
	int ret =  -1;
	char errbuf[512];
	size_t errlen =sizeof(errbuf);
	ret = asn_check_constraints(&asn_DEF_Ngap_NGAP_PDU, pdu, errbuf, &errlen);
	if(ret != 0) 
	{
		printf("Constraint validation  failed:%s\n", errbuf);
	}
	return ret;
}


int ngap_amf_decode_pdu(Ngap_NGAP_PDU_t *pdu, const_bstring const raw)
{
	Ngap_NGAP_PDU_t                     *decoded_pdu = pdu;
   
    asn_dec_rval_t rc = asn_decode(NULL,ATS_ALIGNED_CANONICAL_PER,&asn_DEF_Ngap_NGAP_PDU,(void**)&decoded_pdu,bdata(raw),blength(raw));
    if(rc.code != RC_OK)
    {
          printf("asn_decode failed(%d)\n",rc.code);
    	  return rc.code; 
    }
	return rc.code;
}



//#include "log.h"
/*

int                                     asn_debug = 0;
int                                     asn1_xer_print = 0;

ssize_t
ngap_generate_unsuccessfull_outcome (
  uint8_t ** buffer,
  uint32_t * length,
  e_Ngap_ProcedureCode procedureCode,
  Ngap_Criticality_t criticality,
  asn_TYPE_descriptor_t * td,
  void *sptr)
{
  NGAP_PDU_t                              pdu;
  ssize_t                                 encoded;

  memset (&pdu, 0, sizeof (NGAP_PDU_t));
  pdu.present = NGAP_PDU_PR_unsuccessfulOutcome;
  pdu.choice.unsuccessfulOutcome.procedureCode = procedureCode;
  pdu.choice.unsuccessfulOutcome.criticality = criticality;
  ANY_fromType (&pdu.choice.unsuccessfulOutcome.value, td, sptr);

  if (asn1_xer_print) {
    xer_fprint (stdout, &asn_DEF_NGAP_PDU, (void *)&pdu);
  }

  ASN_STRUCT_FREE_CONTENTS_ONLY (*td, sptr);

  if ((encoded = uper_encode_to_new_buffer (&asn_DEF_NGAP_PDU, 0, &pdu, (void **)buffer)) < 0) {
    OAILOG_ERROR (LOG_NGAP, "Encoding of %s failed\n", td->name);
    return -1;
  }

  *length = encoded;
  return encoded;
}

ssize_t
ngap_generate_initiating_message (
  uint8_t ** buffer,
  uint32_t * length,
  e_Ngap_ProcedureCode procedureCode,
  Ngap_Criticality_t criticality,
  asn_TYPE_descriptor_t * td,
  void *sptr)
{
  NGAP_PDU_t                              pdu;
  ssize_t                                 encoded;

  memset (&pdu, 0, sizeof (NGAP_PDU_t));
  pdu.present = NGAP_PDU_PR_initiatingMessage;
  pdu.choice.initiatingMessage.procedureCode = procedureCode;
  pdu.choice.initiatingMessage.criticality = criticality;
  ANY_fromType (&pdu.choice.initiatingMessage.value, td, sptr);

  if (asn1_xer_print) {
    xer_fprint (stdout, &asn_DEF_NGAP_PDU, (void *)&pdu);
  }

  ASN_STRUCT_FREE_CONTENTS_ONLY (*td, sptr);

  if ((encoded = uper_encode_to_new_buffer (&asn_DEF_NGAP_PDU, 0, &pdu, (void **)buffer)) < 0) {
    OAILOG_ERROR (LOG_NGAP, "Encoding of %s failed\n", td->name);
    return -1;
  }

  *length = encoded;
  return encoded;
}


Ngap_IE_t                              *
ngap_new_ie (
  Ngap_ProtocolIE_ID_t id,
  Ngap_Criticality_t criticality,
  asn_TYPE_descriptor_t * type,
  void *sptr)
{
  Ngap_IE_t                              *buff;
  
  if ((buff = malloc (sizeof (Ngap_IE_t))) == NULL) {
    // Possible error on malloc
    return NULL;
  }
  
  memset ((void *)buff, 0, sizeof (Ngap_IE_t));
  buff->id = id;
  buff->criticality = criticality;
  
  if (ANY_fromType (&buff->value, type, sptr) < 0) {
    OAILOG_ERROR (LOG_NGAP, "Encoding of %s failed\n", type->name);
    free_wrapper ((void**) &buff);
    return NULL;
  }
  
  if (asn1_xer_print)
    if (xer_fprint (stdout, &asn_DEF_Ngap_IE, buff) < 0) {
      free_wrapper ((void**) &buff);
      return NULL;
    }
  
  return buff;
}
*/
