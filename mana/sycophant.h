/*
 * hostapd-mana sycophant helpers
 */

#ifndef MANA_SYCOPHANT_H
#define MANA_SYCOPHANT_H

#include "utils/common.h"

struct wpabuf;

void mana_sycophant_mschapv2_challenge(u8 *auth_challenge, size_t len);
void mana_sycophant_mschapv2_response(const struct wpabuf *resp);

#endif /* MANA_SYCOPHANT_H */
