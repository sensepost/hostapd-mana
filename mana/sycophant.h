/*
 * hostapd-mana sycophant socket helpers
 */

#ifndef MANA_SYCOPHANT_H
#define MANA_SYCOPHANT_H

#include "utils/includes.h"
#include "utils/common.h"

int mana_sycophant_init(void);
void mana_sycophant_deinit(void);
void mana_sycophant_identity(int phase, const u8 *identity,
			     size_t identity_len);
int mana_sycophant_mschapv2_challenge(u8 *challenge, size_t len);
void mana_sycophant_mschapv2_response(const u8 *response, size_t len);

#endif /* MANA_SYCOPHANT_H */
