hostapd-mana
============

## Overview

A featureful rogue access point first presented at [Defcon 22](https://www.youtube.com/watch?v=i2-jReLBSVk) by Dominic White ([@singe](https://twitter.com/singe)) & Ian de Villiers @ sensepost (research@sensepost.com)

## Documentation

Check [the wiki](https://github.com/sensepost/hostapd-mana/wiki) for information of getting and using hostapd-mana.

## Features

* KARMA/MANA Mode - respond to any device looking for an SSID as that network (probe response)
* MANA Loud - re-broadcast probe responses for SSIDs learned from other devices
* Taxonomy Signatures - Capture partial and full taxonomy signatures for pre-assoc/assoc stations for deanonymisation of random MACs
* SSID allow list - Only allow certain SSIDs to be rebroadcast
* MANA MAC ACLs - proportionality options to define flexible ACLs to only respond to specific stations, manufacturers or random/non-random MACs
* WPE EAP Credential Capture - Capture recoverable credential material from *over 16* different EAP modes
* EAP-TLS - Accept any client certificate for stations that don't perform proper server cert validation
* EAP Sycophant - Relay inner PEAP using the sycophant supplicant to get a dual client association and association to target network without cracking password
* EAP Success - Send EAP Success even when EAP fails, some supplicants will forget the EAP auth failed and join anyway
* WPA2 Half-Handshake Capture - Capture WPA2 half-handshakes (in hashcat mode 22000) for unseen networks (with MANA mode)

## License

The patches included in hostapd-mana by SensePost are licensed under the BSD license. Permissions beyond the scope of this license may be available at http://sensepost.com/contact us/. hostapd's code retains it's original license available in [COPYING](https://github.com/sensepost/hostapd-mana/blob/master/COPYING).
