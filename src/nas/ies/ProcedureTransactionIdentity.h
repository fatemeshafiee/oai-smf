#include <stdint.h>
#include "bstrlib.h"

#define PROCEDURE_TRANSACTION_IDENTITY_MINIMUM_LENGTH 1
#define PROCEDURE_TRANSACTION_IDENTITY_MAXIMUM_LENGTH 1

typedef bstring ProcedureTransactionIdentity;

int encode_procedure_transaction_identity ( ProcedureTransactionIdentity proceduretransactionidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;
int decode_procedure_transaction_identity ( ProcedureTransactionIdentity * proceduretransactionidentity, uint8_t iei, uint8_t * buffer, uint32_t len  ) ;

