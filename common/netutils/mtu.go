/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package netutils

import "sync"

var (
	ethernetMtu = 9000
	mtuMux      sync.RWMutex
)

func UpdateEthernetMtu(mtu int) {
	mtuMux.Lock()
	defer mtuMux.Unlock()
	if mtu < ethernetMtu {
		ethernetMtu = mtu
	}
}

func GetEthernetMtu() int {
	mtuMux.RLock()
	defer mtuMux.RUnlock()
	return ethernetMtu
}
