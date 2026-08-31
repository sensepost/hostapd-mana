# hostapd-mana hwsim tests
#
# This software may be distributed under the terms of the BSD license.

import os
import tempfile

import hostapd
from test_ap_eap import check_eap_capa, eap_connect


def test_ap_wpa2_eap_peap_wpe(dev, apdev):
    """PEAP WPE uses the MANA phase-2 test identity and captures output"""
    check_eap_capa(dev[0], "MSCHAPV2")
    credout = tempfile.NamedTemporaryFile(prefix="mana-peap-", delete=False)
    credout.close()
    params = {"ssid": "test-wpa2-eap", "wpa": "2",
              "wpa_key_mgmt": "WPA-EAP", "rsn_pairwise": "CCMP",
              "ieee8021x": "1", "eap_server": "1",
              "eap_user_file": "auth_serv/eap_user.conf",
              "ca_cert": "auth_serv/ca.pem",
              "server_cert": "auth_serv/server.pem",
              "private_key": "auth_serv/server.key",
              "mana_wpe": "1", "mana_eapsuccess": "1",
              "mana_credout": credout.name}
    hapd = hostapd.add_ap(apdev[0], params)

    try:
        eap_connect(dev[0], hapd, "PEAP", "user", password="wrong",
                    ca_cert="auth_serv/ca.pem", phase2="auth=MSCHAPV2",
                    expect_failure=True, maybe_local_error=True)
        with open(credout.name, "r") as f:
            data = f.read()
        if "EAP-MSCHAPV2 HASHCAT" not in data:
            raise Exception("Expected MANA MSCHAPv2 capture missing")
    finally:
        dev[0].request("REMOVE_NETWORK all")
        try:
            os.unlink(credout.name)
        except OSError:
            pass


def test_ap_wpa2_eap_tls_mana_eaptls(dev, apdev):
    """MANA EAP-TLS test mode accepts an otherwise untrusted client cert"""
    params = {"ssid": "test-wpa2-eap", "wpa": "2",
              "wpa_key_mgmt": "WPA-EAP", "rsn_pairwise": "CCMP",
              "ieee8021x": "1", "eap_server": "1",
              "eap_user_file": "auth_serv/eap_user.conf",
              "ca_cert": "auth_serv/ca.pem",
              "server_cert": "auth_serv/server.pem",
              "private_key": "auth_serv/server.key"}

    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TLS", "tls user",
                ca_cert="auth_serv/ca.pem",
                client_cert="auth_serv/ec-user.pem",
                private_key="auth_serv/ec-user.key", expect_failure=True,
                maybe_local_error=True)
    dev[0].request("REMOVE_NETWORK all")

    params["mana_eaptls"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)
    eap_connect(dev[0], hapd, "TLS", "tls user",
                ca_cert="auth_serv/ca.pem",
                client_cert="auth_serv/ec-user.pem",
                private_key="auth_serv/ec-user.key")
