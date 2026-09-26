/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2026 zeropentime authors. Added to the WireGuard firewall
 * package for zeropentime: permit traffic to chosen networks (the LAN).
 */

package wgfirewall

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// permitRemoteNets permits traffic to and from the given networks on any
// interface. Conditions on the same field are OR'ed by WFP, so one filter
// per layer covers all networks of a family.
func permitRemoteNets(session uintptr, baseObjects *baseObjects, weight uint8, nets []netip.Prefix) error {
	var v4, v6 []wtFwpmFilterCondition0
	var keep4 []*wtFwpV4AddrAndMask
	var keep6 []*wtFwpV6AddrAndMask
	for _, p := range nets {
		p = p.Masked()
		if p.Addr().Is4() {
			m := &wtFwpV4AddrAndMask{
				addr: binary.BigEndian.Uint32(p.Addr().AsSlice()),
				mask: ^uint32(0) << (32 - p.Bits()),
			}
			if p.Bits() == 0 {
				m.mask = 0
			}
			keep4 = append(keep4, m)
			v4 = append(v4, wtFwpmFilterCondition0{
				fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType:      cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{_type: cFWP_V4_ADDR_MASK, value: uintptr(unsafe.Pointer(m))},
			})
		} else {
			m := &wtFwpV6AddrAndMask{addr: p.Addr().As16(), prefixLength: uint8(p.Bits())}
			keep6 = append(keep6, m)
			v6 = append(v6, wtFwpmFilterCondition0{
				fieldKey:       cFWPM_CONDITION_IP_REMOTE_ADDRESS,
				matchType:      cFWP_MATCH_EQUAL,
				conditionValue: wtFwpConditionValue0{_type: cFWP_V6_ADDR_MASK, value: uintptr(unsafe.Pointer(m))},
			})
		}
	}
	add := func(conds []wtFwpmFilterCondition0, layer windows.GUID, name string) error {
		if len(conds) == 0 {
			return nil
		}
		displayData, err := createWtFwpmDisplayData0(name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conds)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conds[0])),
			action:              wtFwpmAction0{_type: cFWP_ACTION_PERMIT},
		}
		filterID := uint64(0)
		return wrapErr(fwpmFilterAdd0(session, &filter, 0, &filterID))
	}
	for _, f := range []struct {
		conds []wtFwpmFilterCondition0
		layer windows.GUID
		name  string
	}{
		{v4, cFWPM_LAYER_ALE_AUTH_CONNECT_V4, "Permit outbound to allowed networks (IPv4)"},
		{v4, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, "Permit inbound from allowed networks (IPv4)"},
		{v6, cFWPM_LAYER_ALE_AUTH_CONNECT_V6, "Permit outbound to allowed networks (IPv6)"},
		{v6, cFWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, "Permit inbound from allowed networks (IPv6)"},
	} {
		if err := add(f.conds, f.layer, f.name); err != nil {
			return err
		}
	}
	runtime.KeepAlive(keep4)
	runtime.KeepAlive(keep6)
	return nil
}
