#include <stdint.h>
#include "bstrlib.h"
#include <stdbool.h>

#define UE_STATUS_MINIMUM_LENGTH 3
#define UE_STATUS_MAXIMUM_LENGTH 3

#define UE_NOT_IN_EMM_REGISTERED 0
#define UE_IN_EMM_REGISTERED     1
#define UE_NOT_IN_5GMM_REGISTERED 0
#define UE_IN_5GMM_REGISTERED     1

typedef struct{
  bool n1_mode_reg;
  bool s1_mode_reg;
} UEStatus;

int encode_ue_status ( UEStatus uestatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_ue_status ( UEStatus * uestatus, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

