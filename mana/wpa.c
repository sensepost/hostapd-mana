/*
 * hostapd-mana WPA helpers
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/eapol_common.h"
#include "common/wpa_common.h"
#include "ap/hostapd.h"
#include "ap/sta_info.h"
#include "ap/wpa_auth.h"
#include "ap/wpa_auth_i.h"
#include "mana/state.h"
#include "mana/wpa.h"

static size_t mana_append_hex(char *buffer, size_t index,
			      const void *data, size_t len)
{
	const u8 *byte_data = data;

	while (len-- > 0)
		index += sprintf(buffer + index, "%02x", *byte_data++);
	return index;
}

void mana_wpa_capture_handshake(struct wpa_authenticator *wpa_auth,
				struct wpa_state_machine *sm,
				const struct ieee802_1x_hdr *hdr,
				const struct wpa_eapol_key *key,
				const u8 *mic, size_t mic_len,
				const u8 *key_data, u16 key_data_length)
{
	size_t hc_out_buf_size;
	char *hc_out_buf;
	const u8 *ssid = wpa_auth->conf.ssid;
	size_t ssid_len = wpa_auth->conf.ssid_len;
	size_t buf_index = 0;
	struct hostapd_data *hapd = wpa_auth->cb_ctx;
	struct sta_info *assoc_sta = NULL;
	bool skip_hashcat = false;
	size_t j;

	wpa_printf(MSG_INFO, "MANA: Captured a WPA/2 handshake from: " MACSTR,
		   MAC2STR(sm->addr));

	if (mana_enabled()) {
		if (hapd)
			assoc_sta = ap_get_sta(hapd, sm->addr);
		if (!assoc_sta || !assoc_sta->mana_assoc_ssid_set) {
			wpa_printf(MSG_DEBUG,
				   "MANA WPA2 HASHCAT: association SSID unavailable for "
				   MACSTR ", skip output", MAC2STR(sm->addr));
			skip_hashcat = true;
		} else {
			ssid = assoc_sta->mana_assoc_ssid;
			ssid_len = assoc_sta->mana_assoc_ssid_len;
		}
	}

	/*
	 * Calculate the buffer size at runtime.
	 * The old fixed 600-byte allocation was too small for valid EAPOL-Key
	 * frames with a sizeable key-data field (e.g., RSN IEs).
	 */
	hc_out_buf_size = 270 + 4 * mic_len + 2 * ssid_len +
		2 * key_data_length;
	hc_out_buf = os_malloc(hc_out_buf_size);
	if (!hc_out_buf) {
		wpa_printf(MSG_ERROR, "MANA WPA2 HASHCAT: out of memory");
		return;
	}
	if (skip_hashcat) {
		os_free(hc_out_buf);
		return;
	}

	buf_index += sprintf(hc_out_buf + buf_index, "WPA*02*");
	buf_index = mana_append_hex(hc_out_buf, buf_index, mic, mic_len);
	buf_index += sprintf(hc_out_buf + buf_index, "*");
	buf_index = mana_append_hex(hc_out_buf, buf_index, sm->wpa_auth->addr, 6);
	buf_index += sprintf(hc_out_buf + buf_index, "*");
	buf_index = mana_append_hex(hc_out_buf, buf_index, sm->addr, 6);
	buf_index += sprintf(hc_out_buf + buf_index, "*");
	buf_index = mana_append_hex(hc_out_buf, buf_index, ssid, ssid_len);
	buf_index += sprintf(hc_out_buf + buf_index, "*");
	buf_index = mana_append_hex(hc_out_buf, buf_index, sm->ANonce,
				    WPA_NONCE_LEN);
	buf_index += sprintf(hc_out_buf + buf_index, "*");
	buf_index = mana_append_hex(hc_out_buf, buf_index, hdr, sizeof(*hdr));
	buf_index = mana_append_hex(hc_out_buf, buf_index, &key->type, 1);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->key_info, 2);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->key_length, 2);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->replay_counter,
				    WPA_REPLAY_COUNTER_LEN);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->key_nonce,
				    WPA_NONCE_LEN);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->key_iv, 16);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->key_rsc,
				    WPA_KEY_RSC_LEN);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key->key_id, 8);
	for (j = 0; j < mic_len; j++)
		buf_index = mana_append_hex(hc_out_buf, buf_index, "\x00", 1);
	buf_index = mana_append_hex(hc_out_buf, buf_index, mic + mic_len, 2);
	buf_index = mana_append_hex(hc_out_buf, buf_index, key_data,
				    key_data_length);
	buf_index += sprintf(hc_out_buf + buf_index, "*00");
	wpa_printf(MSG_INFO, "MANA WPA2 HASHCAT | %s", hc_out_buf);

	if (mana.conf && os_strcmp("NOT_SET", mana.conf->mana_wpaout) != 0) {
		FILE *f = fopen(mana.conf->mana_wpaout, "a");

		if (f) {
			fprintf(f, "[WPA2-EAPOL HASHCAT]\t%s\n", hc_out_buf);
			fclose(f);
		}
	}
	os_free(hc_out_buf);
}

int mana_wpa_should_suppress_disconnect(const u8 *addr, u16 reason)
{
	if (mana_enabled() && os_strcmp("NOT_SET", mana.conf->mana_wpaout) != 0) {
		wpa_printf(MSG_DEBUG,
			   "MANA: suppress WPA disconnect for STA " MACSTR
			   " reason %u", MAC2STR(addr), reason);
		return 1;
	}

	return 0;
}
