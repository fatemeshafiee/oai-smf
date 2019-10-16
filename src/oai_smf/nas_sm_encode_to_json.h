#ifndef _NAS_SM_ENCODE_TO_JSON_H_
#define _NAS_SM_ENCODE_TO_JSON_H_

int sm_encode_establishment_request(void);
//int sm_encode_establishment_accept(void);
int sm_encode_establishment_reject(void);
int sm_encode_authentication_command(void);
int sm_encode_authentication_complete(void);
int sm_encode_authentication_result(void);
//int sm_encode_modification_request(void);
int sm_encode_modification_reject(void);
//int sm_encode_modification_command(void);
int sm_encode_modification_complete(void);
int sm_encode_modification_command_reject(void);
int sm_encode_release_request(void);
int sm_encode_release_reject(void);
int sm_encode_release_command(void);
int sm_encode_release_complete(void);
int sm_encode__5gsm_status_(void);

#endif
