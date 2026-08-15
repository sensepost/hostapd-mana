/*
 * hostapd-mana WPA helpers
 */

#ifndef MANA_WPA_H
#define MANA_WPA_H

#include "utils/common.h"

struct ieee802_1x_hdr;
struct wpa_authenticator;
struct wpa_eapol_key;
struct wpa_state_machine;

void mana_wpa_capture_handshake(struct wpa_authenticator *wpa_auth,
				struct wpa_state_machine *sm,
				const struct ieee802_1x_hdr *hdr,
				const struct wpa_eapol_key *key,
				const u8 *mic, size_t mic_len,
				const u8 *key_data, u16 key_data_length);
int mana_wpa_should_suppress_disconnect(const u8 *addr, u16 reason);

#endif /* MANA_WPA_H */
