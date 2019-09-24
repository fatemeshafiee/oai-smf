#include "bstrlib.h"
#include "common_types.h"
#include "securityDef.h"

/* Type of security context */
typedef enum {
  SECURITY_CTX_TYPE_NOT_AVAILABLE = 0,
  SECURITY_CTX_TYPE_PARTIAL_NATIVE,
  SECURITY_CTX_TYPE_FULL_NATIVE,
  SECURITY_CTX_TYPE_MAPPED             // UNUSED
} fivegmm_sc_type_t;

typedef struct fivegmm_security_context_s {
  fivegmm_sc_type_t sc_type;     /* Type of security context        */  //33401
                      /* state of security context is implicit due to its storage location (current/non-current)*/
#define EKSI_MAX_VALUE 6
  ksi_t ksi;           /* NAS key set identifier for E-UTRAN      */
#define FIVEGMM_SECURITY_VECTOR_INDEX_INVALID (-1)
  int vector_index;   /* Pointer on vector */
  uint8_t knas_enc[AUTH_KNAS_ENC_SIZE];/* NAS cyphering key               */
  uint8_t knas_int[AUTH_KNAS_INT_SIZE];/* NAS integrity key               */

  struct count_s{
    uint32_t spare:8;
    uint32_t overflow:16;
    uint32_t seq_num:8;
  } dl_count, ul_count;   /* Downlink and uplink count parameters    */
  struct {
    uint8_t fivegs_encryption;   /* algorithm used for ciphering            */
    uint8_t fivegs_integrity;    /* algorithm used for integrity protection */
    uint8_t umts_encryption;  /* algorithm used for ciphering            */
    uint8_t umts_integrity;   /* algorithm used for integrity protection */
    uint8_t gprs_encryption;  /* algorithm used for ciphering            */
    bool    umts_present:1;
    bool    gprs_present:1;
  } capability;       /* UE network capability           */
  struct {
    uint8_t encryption:4;   /* algorithm used for ciphering           */
    uint8_t integrity:4;    /* algorithm used for integrity protection */
  } selected_algorithms;       /* AMF selected algorithms                */

  uint8_t   activated;
} fivegmm_security_context_t;
