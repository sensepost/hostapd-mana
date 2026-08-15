/*
 * hostapd-mana EAP/WPE helpers
 */

#ifndef MANA_EAP_H
#define MANA_EAP_H

#include "utils/common.h"

struct eap_sm;

int mana_wpe_enabled(void);
int mana_eapsuccess_enabled(void);
int mana_eaptls_accept_any_cert(void);
void mana_eap_user_get_identity(struct eap_sm *sm, const u8 **identity,
				size_t *identity_len, int phase2);
void eap_server_mschap_rx_callback(struct eap_sm *sm, const char *source,
				   const u8 *username, size_t username_len,
				   const u8 *challenge, const u8 *response);
void eap_server_chap_rx_callback(struct eap_sm *sm, const char *source,
				 const u8 *username, size_t username_len,
				 const u8 *hash, const u8 *salt, u8 id);
void eap_server_pap_rx_callback(struct eap_sm *sm, const char *source,
				const u8 *username, size_t username_len,
				const u8 *password, size_t password_len);

#endif /* MANA_EAP_H */
