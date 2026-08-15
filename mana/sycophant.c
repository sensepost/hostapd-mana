/*
 * hostapd-mana sycophant helpers
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/wpabuf.h"
#include "mana/state.h"
#include "mana/sycophant.h"

static int mana_sycophant_active(void)
{
	return mana.conf && mana.conf->enable_sycophant &&
		os_strcmp("NOT_SET", mana.conf->sycophant_dir) != 0;
}

void mana_sycophant_mschapv2_challenge(u8 *auth_challenge, size_t len)
{
	char sup_state[2] = "*";
	FILE *sycophant_state;

	if (!mana_sycophant_active())
		return;

	wpa_printf(MSG_DEBUG, "SYCOPHANT: Checking Sycophant State File. (%s)",
		   mana.conf->sycophant_state_file);

	while (os_strcmp(sup_state, "C") != 0) {
		sycophant_state = fopen(mana.conf->sycophant_state_file, "rb");
		if (!sycophant_state) {
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Unable to open state file %s, not relaying",
				   mana.conf->sycophant_state_file);
			break;
		}
		fread(sup_state, 1, 1, sycophant_state);
		if (os_strcmp(sup_state, "Z") == 0) {
			wpa_printf(MSG_DEBUG, "SYCOPHANT: State file is Z bailing!");
			fclose(sycophant_state);
			break;
		}
		fclose(sycophant_state);
		usleep(10000);
	}

	if (os_strcmp(sup_state, "C") == 0) {
		FILE *challenge_in;

		wpa_printf(MSG_DEBUG,
			   "SYCOPHANT: State file says we have a challenge.");
		challenge_in = fopen(mana.conf->sycophant_challenge_file, "rb");
		if (!challenge_in) {
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Could not open challenge file %s",
				   mana.conf->sycophant_challenge_file);
			return;
		}
		fseek(challenge_in, 0, SEEK_END);
		if (ftell(challenge_in) > 0) {
			rewind(challenge_in);
			fread(auth_challenge, len, 1, challenge_in);
			wpa_hexdump(MSG_DEBUG, "SYCOPHANT: Incoming MSCHAPv2 challenge",
				    auth_challenge, len);
			fclose(challenge_in);
			challenge_in = fopen(mana.conf->sycophant_challenge_file, "wb");
		} else {
			usleep(1000);
		}
		if (challenge_in)
			fclose(challenge_in);
	}
}

void mana_sycophant_mschapv2_response(const struct wpabuf *resp)
{
	char sup_state[2] = "*";
	FILE *sycophant_state;

	if (!mana_sycophant_active())
		return;

	wpa_printf(MSG_ERROR, "using SYCOPHANT_STATE file : %s",
		   mana.conf->sycophant_state_file);
	sycophant_state = fopen(mana.conf->sycophant_state_file, "rb");
	if (sycophant_state) {
		wpa_printf(MSG_DEBUG, "SYCOPHANT: Checking state file.");
		fread(sup_state, 1, 1, sycophant_state);
		fclose(sycophant_state);
	} else {
		wpa_printf(MSG_ERROR,
			   "SYCOPHANT: Unable to open state file %s, not relaying",
			   mana.conf->sycophant_state_file);
	}

	if (os_strcmp(sup_state, "C") == 0) {
		FILE *response_out;

		wpa_printf(MSG_DEBUG,
			   "SYCOPHANT: State file at Challenge, write the Response.");
		response_out = fopen(mana.conf->sycophant_response_file, "wb");
		if (!response_out) {
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Could not open response file %s",
				   mana.conf->sycophant_response_file);
			return;
		}
		fwrite(resp->buf, resp->used, 1, response_out);
		wpa_hexdump(MSG_DEBUG, "SYCOPHANT: Response to be sent to supplicant",
			    resp->buf, resp->used);
		fclose(response_out);

		sycophant_state = fopen(mana.conf->sycophant_state_file, "wb");
		if (sycophant_state) {
			sup_state[0] = 'R';
			fwrite(sup_state, 1, 1, sycophant_state);
			fclose(sycophant_state);
			wpa_printf(MSG_INFO,
				   "SYCOPHANT: MSCHAPv2 Response handed off to supplicant.");
		} else {
			wpa_printf(MSG_ERROR,
				   "SYCOPHANT: Unable to open state file %s",
				   mana.conf->sycophant_state_file);
		}
	}
}
