#define NAS_INITIAL_UE_MESSAGE(mSGpTR)      (mSGpTR)->ittiMsg.ue_initial_ue_message
#define NGAP_UL_DATA_IND(mSGpTR)              (mSGpTR)->ittiMsg.ngap_data_ind
#define NAS_MM_DL_DATA_REQ(mSGpTR)              (mSGpTR)->ittiMsg.nas_mm_dl_data_req


typedef struct{
  amf_ue_ngap_id_t  ue_id;
  bstring           nas_msg;
  tai_t             tai;
  cgi_t             cgi;
}ngap_data_ind_t;

/*
 * AS->NAS - NAS signalling connection establishment indication
 * AS transfers the initial NAS message to the NAS.
 */
typedef struct nas_establish_ind_s {
  amf_ue_ngap_id_t ue_id;             /* UE lower layer identifier               */
  tai_t            tai;               /* Indicating the Tracking Area from which the UE has sent the NAS message.                         */
  cgi_t            cgi;               /* Indicating the cell from which the UE has sent the NAS message.                         */
  //as_cause_t       as_cause;          /* Establishment cause                     */
  //as_stmsi_t       s_tmsi;            /* UE identity optional field, if not present, value is NOT_A_S_TMSI */
  bstring          initial_nas_msg;   /* Initial NAS message to transfer         */
} nas_establish_ind_t;

typedef struct itti_nas_initial_ue_message_s {
  nas_establish_ind_t nas;

  /* Transparent message from ngap to be forwarded to AMF_APP or
   * to NGAP if connection establishment is rejected by NAS.
   */
  itti_ngap_initial_ue_message_t transparent;
} itti_nas_initial_ue_message_t;
