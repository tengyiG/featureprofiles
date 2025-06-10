// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package mpls_in_udp_test implements TE-18.1 MPLS-in-UDP encapsulation tests
package mpls_in_udp_test

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/gribi"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/gribigo/client"
	"github.com/openconfig/gribigo/constants"
	"github.com/openconfig/gribigo/fluent"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygot/ygot"
)

const (
	ipipProtocol       = 4
	ipv6ipProtocol     = 41
	udpProtocol        = 17
	ethertypeIPv4      = oc.PacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4
	ethertypeIPv6      = oc.PacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6
	clusterPolicy      = "vrf_selection_policy_c"
	ipv4PrefixLen      = 30
	ipv6PrefixLen      = 126
	trafficDuration    = 15 * time.Second
	nhg10ID            = 10
	nh201ID            = 201
	nh202ID            = 202
	nhg1ID             = 1
	nh1ID              = 1
	nh2ID              = 2
	nhg2ID             = 2
	nh10ID             = 10
	nh11ID             = 11
	nhg3ID             = 3
	nh100ID            = 100
	nh101ID            = 101
	dscpEncapA1        = 10
	dscpEncapA2        = 18
	dscpEncapB1        = 20
	dscpEncapB2        = 28
	dscpEncapNoMatch   = 30
	magicIP            = "192.168.1.1"
	magicMac           = "02:00:00:00:00:01"
	tunnelDstIP1       = "203.0.113.1"
	tunnelDstIP2       = "203.0.113.2"
	ipv4OuterSrc111    = "198.51.100.111"
	ipv4OuterSrc222    = "198.51.100.222"
	ipv4OuterSrcIPInIP = "198.100.200.123"
	vipIP1             = "192.0.2.111"
	vipIP2             = "192.0.2.222"
	innerV4DstIP       = "198.18.1.1"
	innerV4SrcIP       = "198.18.0.255"
	InnerV6SrcIP       = "2001:DB8::198:1"
	InnerV6DstIP       = "2001:DB8:2:0:192::10"
	ipv4FlowIP         = "138.0.11.8"
	ipv4EntryPrefix    = "138.0.11.0"
	ipv4EntryPrefixLen = 24
	ipv6FlowIP         = "2015:aa8::1"
	ipv6EntryPrefix    = "2015:aa8::"
	ipv6EntryPrefixLen = 64
	ratioTunEncap1     = 0.25 // 1/4
	ratioTunEncap2     = 0.75 // 3/4
	ratioTunEncapTol   = 0.05 // 5/100
	ttl                = uint32(100)
	trfDistTolerance   = 0.02
	// observing on IXIA OTG: Cannot start capture on more than one port belonging to the
	// same resource group or on more than one port behind the same front panel port in the chassis
	otgMutliPortCaptureSupported = false
	seqIDBase                    = uint32(10)

	// MPLS-in-UDP constants
	mplsLabel       = uint64(100)
	outerIPv6Src    = "2001:db8::1"
	outerIPv6Dst    = "2001:db8::100"
	outerSrcUDPPort = uint16(6635)
	outerDstUDPPort = uint16(6635)
	outerIPTTL      = uint8(64)
	outerDscp       = uint8(10)
	innerIPv6Prefix = "2001:db8:1::/64"

	// MPLS-in-UDP entry IDs (using high numbers to avoid conflicts)
	mplsNHID  = uint64(1001)
	mplsNHGID = uint64(2001)
)

var (
	otgDstPorts = []string{"port2"}
	otgSrcPort  = "port1"
	wantWeights = []float64{
		0.0625, // 1/4 * 1/4 - port1
		0.1875, // 1/4 * 3/4 - port2
	}
	noMatchWeight = []float64{
		1, 0, 0, 0,
	}
)

var (
	dutPort1 = attrs.Attributes{
		Desc:    "dutPort1",
		MAC:     "02:01:00:00:00:01",
		IPv4:    "192.0.2.1",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::1",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort1 = attrs.Attributes{
		Name:    "otgPort1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:0db8::192:0:2:2",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort2 = attrs.Attributes{
		Desc:    "dutPort2",
		IPv4:    "192.0.2.5",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:0db8::192:0:2:5",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort2 = attrs.Attributes{
		Name:    "otgPort2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:0db8::192:0:2:6",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort2DummyIP = attrs.Attributes{
		Desc:       "dutPort2",
		IPv4Sec:    "192.0.2.21",
		IPv4LenSec: ipv4PrefixLen,
	}

	otgPort2DummyIP = attrs.Attributes{
		Desc:    "otgPort2",
		IPv4:    "192.0.2.22",
		IPv4Len: ipv4PrefixLen,
	}
)

type pbrRule struct {
	sequence    uint32
	protocol    uint8
	srcAddr     string
	dscpSet     []uint8
	dscpSetV6   []uint8
	decapVrfSet []string
	encapVrf    string
	etherType   oc.NetworkInstance_PolicyForwarding_Policy_Rule_L2_Ethertype_Union
}

type packetAttr struct {
	dscp     int
	protocol int
	ttl      uint32
}

type flowAttr struct {
	src      string   // source IP address
	dst      string   // destination IP address
	srcPort  string   // source OTG port
	dstPorts []string // destination OTG ports
	srcMac   string   // source MAC address
	dstMac   string   // destination MAC address
	topo     gosnappi.Config
}

var (
	fa4 = flowAttr{
		src:      otgPort1.IPv4,
		dst:      ipv4FlowIP,
		srcMac:   otgPort1.MAC,
		dstMac:   dutPort1.MAC,
		srcPort:  otgSrcPort,
		dstPorts: otgDstPorts,
		topo:     gosnappi.NewConfig(),
	}
	fa6 = flowAttr{
		src:      otgPort1.IPv6,
		dst:      ipv6FlowIP,
		srcMac:   otgPort1.MAC,
		dstMac:   dutPort1.MAC,
		srcPort:  otgSrcPort,
		dstPorts: otgDstPorts,
		topo:     gosnappi.NewConfig(),
	}
	faIPinIP = flowAttr{
		src:      ipv4OuterSrcIPInIP,
		dst:      ipv4FlowIP,
		srcMac:   otgPort1.MAC,
		dstMac:   dutPort1.MAC,
		srcPort:  otgSrcPort,
		dstPorts: otgDstPorts,
		topo:     gosnappi.NewConfig(),
	}
)

// testArgs holds the objects needed by a test case.
type testArgs struct {
	dut    *ondatra.DUTDevice
	ate    *ondatra.ATEDevice
	topo   gosnappi.Config
	client *gribi.Client
}

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func TestMPLSOUDPEncap(t *testing.T) {
	// Configure DUT
	dut := ondatra.DUT(t, "dut")
	configureDUT(t, dut)

	// Configure ATE
	otg := ondatra.ATE(t, "ate")
	topo := configureOTG(t, otg)

	// configure gRIBI client
	c := gribi.Client{
		DUT:         dut,
		FIBACK:      true,
		Persistence: true,
	}

	if err := c.Start(t); err != nil {
		t.Fatalf("gRIBI Connection can not be established")
	}

	defer c.Close(t)
	c.BecomeLeader(t)

	// Flush all existing AFT entries on the router
	c.FlushAll(t)

	programEntries(t, dut, &c)

	test := []struct {
		name               string
		pattr              packetAttr
		flows              []gosnappi.Flow
		weights            []float64
		capturePorts       []string
		validateEncapRatio bool
		mplsConfig         *mplsInUDPConfig // MPLS-in-UDP configuration for this test
	}{
		{
			name:               fmt.Sprintf("MPLS-in-UDP IPv6 Traffic Encap dscp %d", dscpEncapA1),
			pattr:              packetAttr{dscp: dscpEncapA1, protocol: udpProtocol, ttl: 63}, // UDP protocol for MPLS-in-UDP, TTL decremented
			flows:              []gosnappi.Flow{fa6.getFlow("ipv6", "ip6a1", dscpEncapA1)},
			weights:            wantWeights,
			capturePorts:       otgDstPorts,
			validateEncapRatio: true,
			mplsConfig: &mplsInUDPConfig{
				nhIndex:     mplsNHID,
				nhgIndex:    mplsNHGID,
				mplsLabel:   mplsLabel,
				outerSrcIP:  outerIPv6Src,
				outerDstIP:  outerIPv6Dst,
				srcUDPPort:  outerSrcUDPPort,
				dstUDPPort:  outerDstUDPPort,
				innerPrefix: innerIPv6Prefix,
				ipTTL:       outerIPTTL,
				dscp:        outerDscp,
			},
		},
	}

	tcArgs := &testArgs{
		client: &c,
		dut:    dut,
		ate:    otg,
		topo:   topo,
	}

	for _, tc := range test {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Name: %s", tc.name)

			// Setup cleanup function for this test case
			defer func() {
				// Clean up MPLS entries if they were added
				if tc.mplsConfig != nil {
					deleteMPLSInUDPEntries(t, dut, tcArgs.client, tc.mplsConfig)
				}
				// Flush all entries to ensure clean state for next test
				tcArgs.client.FlushAll(t)
				// Re-add basic infrastructure for next test
				programEntries(t, dut, tcArgs.client)
			}()

			// Add MPLS-in-UDP entries if this test requires them
			if tc.mplsConfig != nil {
				addMPLSInUDPEntries(t, dut, tcArgs.client, tc.mplsConfig)
			}

			if strings.Contains(tc.name, "No Match Dscp") {
				configDefaultRoute(t, dut, cidr(ipv4EntryPrefix, ipv4EntryPrefixLen), otgPort2.IPv4, cidr(ipv6EntryPrefix, ipv6EntryPrefixLen), otgPort2.IPv6)
				defer gnmi.Delete(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).Static(cidr(ipv4EntryPrefix, ipv4EntryPrefixLen)).Config())
				defer gnmi.Delete(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).Static(cidr(ipv6EntryPrefix, ipv6EntryPrefixLen)).Config())
			}
			if otgMutliPortCaptureSupported {
				enableCapture(t, otg.OTG(), topo, tc.capturePorts)
				t.Log("Start capture and send traffic")
				sendTraffic(t, tcArgs, tc.flows, true)
				t.Log("Validate captured packet attributes")
				tunCounter := validatePacketCapture(t, tcArgs, tc.capturePorts, &tc.pattr)
				if tc.validateEncapRatio {
					validateTunnelEncapRatio(t, tunCounter)
				}
				clearCapture(t, otg.OTG(), topo)
			} else {
				for _, port := range tc.capturePorts {
					enableCapture(t, otg.OTG(), topo, []string{port})
					t.Log("Start capture and send traffic")
					sendTraffic(t, tcArgs, tc.flows, true)
					t.Log("Validate captured packet attributes")
					tunCounter := validatePacketCapture(t, tcArgs, []string{port}, &tc.pattr)
					if tc.validateEncapRatio {
						validateTunnelEncapRatio(t, tunCounter)
					}
					clearCapture(t, otg.OTG(), topo)
				}
			}
			t.Log("Validate traffic flows")
			validateTrafficFlows(t, tcArgs, tc.flows, false, true)
			t.Log("Validate hierarchical traffic distribution")
			validateTrafficDistribution(t, otg, tc.weights)
		})
	}
}

// getPbrRules returns pbrRule slice for cluster facing (clusterFacing = true) or wan facing
// interface (clusterFacing = false)
func getPbrRules(dut *ondatra.DUTDevice) []pbrRule {
	vrfDefault := deviations.DefaultNetworkInstance(dut)

	if deviations.PfRequireMatchDefaultRule(dut) {
		return []pbrRule{
			{
				sequence:  17,
				etherType: ethertypeIPv4,
				encapVrf:  vrfDefault,
			},
			{
				sequence:  18,
				etherType: ethertypeIPv6,
				encapVrf:  vrfDefault,
			},
		}
	} else {
		return []pbrRule{
			{
				sequence: 17,
				encapVrf: vrfDefault,
			},
		}
	}
}

// seqIDOffset returns sequence ID offset added with seqIDBase (10), to avoid sequences
// like 1, 10, 11, 12,..., 2, 21, 22, ... while being sent by Ondatra to the DUT.
// It now generates sequences like 11, 12, 13, ..., 19, 20, 21,..., 99.
func seqIDOffset(dut *ondatra.DUTDevice, i uint32) uint32 {
	if deviations.PfRequireSequentialOrderPbrRules(dut) {
		return i + seqIDBase
	}
	return i
}

// configDefaultRoute configures a static route in DEFAULT network-instance.
func configDefaultRoute(t *testing.T, dut *ondatra.DUTDevice, v4Prefix, v4NextHop, v6Prefix, v6NextHop string) {
	t.Logf("Configuring static route in DEFAULT network-instance")
	ni := oc.NetworkInstance{Name: ygot.String(deviations.DefaultNetworkInstance(dut))}
	static := ni.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut))
	sr := static.GetOrCreateStatic(v4Prefix)
	nh := sr.GetOrCreateNextHop("0")
	nh.NextHop = oc.UnionString(v4NextHop)
	gnmi.Update(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).Config(), static)
	sr = static.GetOrCreateStatic(v6Prefix)
	nh = sr.GetOrCreateNextHop("0")
	nh.NextHop = oc.UnionString(v6NextHop)
	gnmi.Update(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).Config(), static)
}

// cidr takes as input the IPv4 address and the Mask and returns the IP string in
// CIDR notation.
func cidr(ipv4 string, ones int) string {
	return ipv4 + "/" + strconv.Itoa(ones)
}

// getPbrPolicy creates PBR rules for cluster
func getPbrPolicy(dut *ondatra.DUTDevice, name string) *oc.NetworkInstance_PolicyForwarding {
	d := &oc.Root{}
	ni := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	pf := ni.GetOrCreatePolicyForwarding()
	p := pf.GetOrCreatePolicy(name)
	p.SetType(oc.Policy_Type_VRF_SELECTION_POLICY)

	for _, pRule := range getPbrRules(dut) {
		r := p.GetOrCreateRule(seqIDOffset(dut, pRule.sequence))
		r4 := r.GetOrCreateIpv4()

		if pRule.dscpSet != nil {
			r4.DscpSet = pRule.dscpSet
		} else if pRule.dscpSetV6 != nil {
			r6 := r.GetOrCreateIpv6()
			r6.DscpSet = pRule.dscpSetV6
		}

		if pRule.protocol != 0 {
			r4.Protocol = oc.UnionUint8(pRule.protocol)
		}

		if pRule.srcAddr != "" {
			r4.SourceAddress = ygot.String(cidr(pRule.srcAddr, 32))
		}

		if len(pRule.decapVrfSet) == 3 {
			ra := r.GetOrCreateAction()
			ra.DecapNetworkInstance = ygot.String(pRule.decapVrfSet[0])
			ra.PostDecapNetworkInstance = ygot.String(pRule.decapVrfSet[1])
			ra.DecapFallbackNetworkInstance = ygot.String(pRule.decapVrfSet[2])
		}
		if deviations.PfRequireMatchDefaultRule(dut) {
			if pRule.etherType != nil {
				r.GetOrCreateL2().Ethertype = pRule.etherType
			}
		}

		if pRule.encapVrf != "" {
			r.GetOrCreateAction().SetNetworkInstance(pRule.encapVrf)
		}
	}
	return pf
}

// configureBaseconfig configures network instances and forwarding policy on the DUT
func configureBaseconfig(t *testing.T, dut *ondatra.DUTDevice) {
	t.Log("Configure default network instance")
	fptest.ConfigureDefaultNetworkInstance(t, dut)
	t.Log("Configure Cluster facing VRF selection Policy")
	pf := getPbrPolicy(dut, clusterPolicy)
	gnmi.Replace(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).PolicyForwarding().Config(), pf)
}

func staticARPWithMagicUniversalIP(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	sb := &gnmi.SetBatch{}
	p2 := dut.Port(t, "port2")
	portList := []*ondatra.Port{p2}
	for idx, p := range portList {
		s := &oc.NetworkInstance_Protocol_Static{
			Prefix: ygot.String(magicIP + "/32"),
			NextHop: map[string]*oc.NetworkInstance_Protocol_Static_NextHop{
				strconv.Itoa(idx): {
					Index: ygot.String(strconv.Itoa(idx)),
					InterfaceRef: &oc.NetworkInstance_Protocol_Static_NextHop_InterfaceRef{
						Interface: ygot.String(p.Name()),
					},
				},
			},
		}
		sp := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut))
		gnmi.BatchUpdate(sb, sp.Static(magicIP+"/32").Config(), s)
		gnmi.BatchUpdate(sb, gnmi.OC().Interface(p.Name()).Config(), configStaticArp(p.Name(), magicIP, magicMac))
	}
	sb.Set(t, dut)
}

// mplsInUDPConfig holds configuration for MPLS-in-UDP encapsulation entries
type mplsInUDPConfig struct {
	nhIndex     uint64
	nhgIndex    uint64
	mplsLabel   uint64
	outerSrcIP  string
	outerDstIP  string
	srcUDPPort  uint16
	dstUDPPort  uint16
	innerPrefix string
	ipTTL       uint8
	dscp        uint8
}

// programEntries pushes basic RIB entries on the DUT required for basic connectivity
// This provides infrastructure for "No Match" scenarios and basic forwarding
func programEntries(t *testing.T, dut *ondatra.DUTDevice, c *gribi.Client) {
	// push basic RIB entries for infrastructure
	if deviations.GRIBIMACOverrideWithStaticARP(dut) {
		c.AddNH(t, nh10ID, "MACwithIp", deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB, &gribi.NHOptions{Dest: otgPort2DummyIP.IPv4, Mac: magicMac})
		c.AddNHG(t, nhg2ID, map[uint64]uint64{nh10ID: 1, nh11ID: 3}, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
		c.AddNHG(t, nhg3ID, map[uint64]uint64{nh100ID: 2, nh101ID: 3}, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
	} else if deviations.GRIBIMACOverrideStaticARPStaticRoute(dut) {
		p2 := dut.Port(t, "port2")
		nh1, op1 := gribi.NHEntry(nh10ID, "MACwithInterface", deviations.DefaultNetworkInstance(dut),
			fluent.InstalledInFIB, &gribi.NHOptions{Interface: p2.Name(), Mac: magicMac, Dest: magicIP})
		nhg1, op5 := gribi.NHGEntry(nhg2ID, map[uint64]uint64{nh10ID: 1, nh11ID: 3},
			deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
		nhg2, op6 := gribi.NHGEntry(nhg3ID, map[uint64]uint64{nh100ID: 2, nh101ID: 3},
			deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
		c.AddEntries(t, []fluent.GRIBIEntry{nh1, nhg1, nhg2},
			[]*client.OpResult{op1, op5, op6})
	} else {
		c.AddNH(t, nh10ID, "MACwithInterface", deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB, &gribi.NHOptions{Interface: dut.Port(t, "port2").Name(), Mac: magicMac})
		c.AddNHG(t, nhg2ID, map[uint64]uint64{nh10ID: 1, nh11ID: 3}, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
		c.AddNHG(t, nhg3ID, map[uint64]uint64{nh100ID: 2, nh101ID: 3}, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
	}
	c.AddIPv4(t, cidr(vipIP1, 32), nhg2ID, deviations.DefaultNetworkInstance(dut), deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)

	c.AddIPv4(t, cidr(vipIP2, 32), nhg3ID, deviations.DefaultNetworkInstance(dut), deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)

	nh5, op7 := gribi.NHEntry(nh1ID, vipIP1, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
	nh6, op8 := gribi.NHEntry(nh2ID, vipIP2, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
	nhg3, op9 := gribi.NHGEntry(nhg1ID, map[uint64]uint64{nh1ID: 1, nh2ID: 3},
		deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
	c.AddEntries(t, []fluent.GRIBIEntry{nh5, nh6, nhg3}, []*client.OpResult{op7, op8, op9})

	nhg4, op11 := gribi.NHGEntry(nhg10ID, map[uint64]uint64{nh201ID: 1, nh202ID: 3},
		deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
	c.AddEntries(t, []fluent.GRIBIEntry{nhg4}, []*client.OpResult{op9, op11})
}

// addMPLSInUDPEntries adds MPLS-in-UDP encapsulation entries for a specific test case
func addMPLSInUDPEntries(t *testing.T, dut *ondatra.DUTDevice, c *gribi.Client, cfg *mplsInUDPConfig) {
	t.Logf("Adding MPLS-in-UDP entries: NH=%d, NHG=%d, Label=%d", cfg.nhIndex, cfg.nhgIndex, cfg.mplsLabel)

	entries := []fluent.GRIBIEntry{
		fluent.NextHopEntry().
			WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithIndex(cfg.nhIndex).
			AddEncapHeader(
				fluent.MPLSEncapHeader().WithLabels(cfg.mplsLabel),
				fluent.UDPV6EncapHeader().
					WithSrcIP(cfg.outerSrcIP).
					WithDstIP(cfg.outerDstIP).
					WithSrcUDPPort(uint64(cfg.srcUDPPort)).
					WithDstUDPPort(uint64(cfg.dstUDPPort)).
					WithIPTTL(uint64(cfg.ipTTL)).
					WithDSCP(uint64(cfg.dscp)),
			),
		fluent.NextHopGroupEntry().
			WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithID(cfg.nhgIndex).
			AddNextHop(cfg.nhIndex, 1),
		fluent.IPv6Entry().
			WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithPrefix(cfg.innerPrefix).
			WithNextHopGroup(cfg.nhgIndex).
			WithNextHopGroupNetworkInstance(deviations.DefaultNetworkInstance(dut)),
	}

	expectedResults := []*client.OpResult{
		fluent.OperationResult().
			WithNextHopOperation(cfg.nhIndex).
			WithProgrammingResult(fluent.InstalledInFIB).
			WithOperationType(constants.Add).
			AsResult(),
		fluent.OperationResult().
			WithNextHopGroupOperation(cfg.nhgIndex).
			WithProgrammingResult(fluent.InstalledInFIB).
			WithOperationType(constants.Add).
			AsResult(),
		fluent.OperationResult().
			WithIPv6Operation(cfg.innerPrefix).
			WithProgrammingResult(fluent.InstalledInFIB).
			WithOperationType(constants.Add).
			AsResult(),
	}

	c.AddEntries(t, entries, expectedResults)
}

// deleteMPLSInUDPEntries removes MPLS-in-UDP encapsulation entries for a specific test case
func deleteMPLSInUDPEntries(t *testing.T, dut *ondatra.DUTDevice, c *gribi.Client, cfg *mplsInUDPConfig) {
	t.Logf("Deleting MPLS-in-UDP entries: NH=%d, NHG=%d, Label=%d", cfg.nhIndex, cfg.nhgIndex, cfg.mplsLabel)

	// Delete in reverse order: IPv6 route -> NHG -> NH
	entries := []fluent.GRIBIEntry{
		fluent.IPv6Entry().
			WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithPrefix(cfg.innerPrefix).
			WithNextHopGroup(cfg.nhgIndex).
			WithNextHopGroupNetworkInstance(deviations.DefaultNetworkInstance(dut)),
		fluent.NextHopGroupEntry().
			WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithID(cfg.nhgIndex).
			AddNextHop(cfg.nhIndex, 1),
		fluent.NextHopEntry().
			WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithIndex(cfg.nhIndex).
			AddEncapHeader(
				fluent.MPLSEncapHeader().WithLabels(cfg.mplsLabel),
				fluent.UDPV6EncapHeader().
					WithSrcIP(cfg.outerSrcIP).
					WithDstIP(cfg.outerDstIP).
					WithSrcUDPPort(uint64(cfg.srcUDPPort)).
					WithDstUDPPort(uint64(cfg.dstUDPPort)).
					WithIPTTL(uint64(cfg.ipTTL)).
					WithDSCP(uint64(cfg.dscp)),
			),
	}

	expectedResults := []*client.OpResult{
		fluent.OperationResult().
			WithIPv6Operation(cfg.innerPrefix).
			WithProgrammingResult(fluent.InstalledInFIB).
			WithOperationType(constants.Delete).
			AsResult(),
		fluent.OperationResult().
			WithNextHopGroupOperation(cfg.nhgIndex).
			WithProgrammingResult(fluent.InstalledInFIB).
			WithOperationType(constants.Delete).
			AsResult(),
		fluent.OperationResult().
			WithNextHopOperation(cfg.nhIndex).
			WithProgrammingResult(fluent.InstalledInFIB).
			WithOperationType(constants.Delete).
			AsResult(),
	}

	c.DeleteEntries(t, entries, expectedResults)
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	d := gnmi.OC()
	p1 := dut.Port(t, "port1")
	p2 := dut.Port(t, "port2")
	portList := []*ondatra.Port{p1, p2}
	dutPortAttrs := []attrs.Attributes{dutPort1, dutPort2}

	// configure interfaces
	for idx, a := range dutPortAttrs {
		p := portList[idx]
		intf := a.NewOCInterface(p.Name(), dut)
		if p.PMD() == ondatra.PMD100GBASELR4 && dut.Vendor() != ondatra.CISCO && dut.Vendor() != ondatra.JUNIPER {
			e := intf.GetOrCreateEthernet()
			if !deviations.AutoNegotiateUnsupported(dut) {
				e.AutoNegotiate = ygot.Bool(false)
			}
			if !deviations.DuplexModeUnsupported(dut) {
				e.DuplexMode = oc.Ethernet_DuplexMode_FULL
			}
			if !deviations.PortSpeedUnsupported(dut) {
				e.PortSpeed = oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB
			}
		}
		if deviations.InterfaceEnabled(dut) {
			s := intf.GetOrCreateSubinterface(0)
			s4 := s.GetOrCreateIpv4()
			s4.Enabled = ygot.Bool(true)
		}

		gnmi.Replace(t, dut, d.Interface(p.Name()).Config(), intf)
	}

	for idx, a := range dutPortAttrs {
		p := portList[idx]
		gnmi.Await(t, dut, d.Interface(p.Name()).Subinterface(0).Ipv6().Address(a.IPv6).Ip().State(), time.Minute, a.IPv6)
	}

	// configure base PBF policies and network-instances
	configureBaseconfig(t, dut)

	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(t, dut, p1.Name(), deviations.DefaultNetworkInstance(dut), 0)
		fptest.AssignToNetworkInstance(t, dut, p2.Name(), deviations.DefaultNetworkInstance(dut), 0)
	}
	// apply PBF to src interface.
	applyForwardingPolicy(t, dut, p1.Name())
	if deviations.GRIBIMACOverrideWithStaticARP(dut) {
		staticARPWithSecondaryIP(t, dut)
	} else if deviations.GRIBIMACOverrideStaticARPStaticRoute(dut) {
		staticARPWithMagicUniversalIP(t, dut)
	}
}

// applyForwardingPolicy applies the forwarding policy on the interface.
func applyForwardingPolicy(t *testing.T, dut *ondatra.DUTDevice, ingressPort string) {
	t.Logf("Applying forwarding policy on interface %v ... ", ingressPort)
	d := &oc.Root{}
	interfaceID := ingressPort
	if deviations.InterfaceRefInterfaceIDFormat(dut) {
		interfaceID = ingressPort + ".0"
	}
	pfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).PolicyForwarding().Interface(interfaceID)
	pfCfg := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut)).GetOrCreatePolicyForwarding().GetOrCreateInterface(interfaceID)
	pfCfg.ApplyVrfSelectionPolicy = ygot.String(clusterPolicy)
	pfCfg.GetOrCreateInterfaceRef().Interface = ygot.String(ingressPort)
	pfCfg.GetOrCreateInterfaceRef().Subinterface = ygot.Uint32(0)
	gnmi.Replace(t, dut, pfPath.Config(), pfCfg)
}

// configreOTG configures port1-5 on the OTG.
func configureOTG(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	otg := ate.OTG()
	topo := gosnappi.NewConfig()
	t.Logf("Configuring OTG port1")
	p1 := ate.Port(t, "port1")
	p2 := ate.Port(t, "port2")

	otgPort1.AddToOTG(topo, p1, &dutPort1)
	otgPort2.AddToOTG(topo, p2, &dutPort2)

	var pmd100GBASELR4 []string
	for _, p := range topo.Ports().Items() {
		port := ate.Port(t, p.Name())
		if port.PMD() == ondatra.PMD100GBASELR4 {
			pmd100GBASELR4 = append(pmd100GBASELR4, port.ID())
		}
	}
	// Disable FEC for 100G-FR ports because Novus does not support it.
	if len(pmd100GBASELR4) > 0 {
		l1Settings := topo.Layer1().Add().SetName("L1").SetPortNames(pmd100GBASELR4)
		l1Settings.SetAutoNegotiate(true).SetIeeeMediaDefaults(false).SetSpeed("speed_100_gbps")
		autoNegotiate := l1Settings.AutoNegotiation()
		autoNegotiate.SetRsFec(false)
	}

	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, topo)
	t.Logf("starting protocols...")
	otg.StartProtocols(t)
	time.Sleep(50 * time.Second)
	otgutils.WaitForARP(t, ate.OTG(), topo, "IPv4")
	otgutils.WaitForARP(t, ate.OTG(), topo, "IPv6")
	return topo
}

// enableCapture enables packet capture on specified list of ports on OTG
func enableCapture(t *testing.T, otg *otg.OTG, topo gosnappi.Config, otgPortNames []string) {
	for _, port := range otgPortNames {
		t.Log("Enabling capture on ", port)
		topo.Captures().Add().SetName(port).SetPortNames([]string{port}).SetFormat(gosnappi.CaptureFormat.PCAP)
	}
	pb, _ := topo.Marshal().ToProto()
	t.Log(pb.GetCaptures())
	otg.PushConfig(t, topo)
}

// clearCapture clears capture from all ports on the OTG
func clearCapture(t *testing.T, otg *otg.OTG, topo gosnappi.Config) {
	t.Log("Clearing capture")
	topo.Captures().Clear()
	otg.PushConfig(t, topo)
}

func randRange(max int, count int) []uint32 {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	var result []uint32
	for len(result) < count {
		result = append(result, uint32(rand.Intn(max)))
	}
	return result
}

// getFlow returns a flow of type ipv4, ipv4in4, ipv6in4 or ipv6 with dscp value passed in args.
func (fa *flowAttr) getFlow(flowType string, name string, dscp uint32) gosnappi.Flow {
	flow := fa.topo.Flows().Add().SetName(name)
	flow.Metrics().SetEnable(true)

	flow.TxRx().Port().SetTxName(fa.srcPort).SetRxNames(fa.dstPorts)
	e1 := flow.Packet().Add().Ethernet()
	e1.Src().SetValue(fa.srcMac)
	e1.Dst().SetValue(fa.dstMac)
	if flowType == "ipv4" || flowType == "ipv4in4" || flowType == "ipv6in4" {
		v4 := flow.Packet().Add().Ipv4()
		v4.Src().SetValue(fa.src)
		v4.Dst().SetValue(fa.dst)
		v4.TimeToLive().SetValue(ttl)
		v4.Priority().Dscp().Phb().SetValue(dscp)

		// add inner ipv4 headers
		if flowType == "ipv4in4" {
			innerV4 := flow.Packet().Add().Ipv4()
			innerV4.Src().SetValue(innerV4SrcIP)
			innerV4.Dst().SetValue(innerV4DstIP)
			innerV4.Priority().Dscp().Phb().SetValue(dscp)
		}

		// add inner ipv6 headers
		if flowType == "ipv6in4" {
			innerV6 := flow.Packet().Add().Ipv6()
			innerV6.Src().SetValue(InnerV6SrcIP)
			innerV6.Dst().SetValue(InnerV6DstIP)
			innerV6.TrafficClass().SetValue(dscp << 2)
		}
	} else if flowType == "ipv6" {
		v6 := flow.Packet().Add().Ipv6()
		v6.Src().SetValue(fa.src)
		v6.Dst().SetValue(fa.dst)
		v6.HopLimit().SetValue(ttl)
		v6.TrafficClass().SetValue(dscp << 2)
	}
	udp := flow.Packet().Add().Udp()
	udp.SrcPort().SetValues(randRange(50001, 10000))
	udp.DstPort().SetValues(randRange(50001, 10000))

	return flow
}

// sendTraffic starts traffic flows and send traffic for a fixed duration
func sendTraffic(t *testing.T, args *testArgs, flows []gosnappi.Flow, capture bool) {
	otg := args.ate.OTG()
	args.topo.Flows().Clear().Items()
	args.topo.Flows().Append(flows...)

	otg.PushConfig(t, args.topo)
	otg.StartProtocols(t)

	otgutils.WaitForARP(t, args.ate.OTG(), args.topo, "IPv4")
	otgutils.WaitForARP(t, args.ate.OTG(), args.topo, "IPv6")

	if capture {
		startCapture(t, args.ate)
		defer stopCapture(t, args.ate)
	}
	t.Log("Starting traffic")
	otg.StartTraffic(t)
	time.Sleep(trafficDuration)
	otg.StopTraffic(t)
	t.Log("Traffic stopped")
}

// validateTrafficFlows verifies that the flow on ATE should pass for good flow and fail for bad flow.
func validateTrafficFlows(t *testing.T, args *testArgs, flows []gosnappi.Flow, capture bool, match bool) {

	otg := args.ate.OTG()
	sendTraffic(t, args, flows, capture)

	otgutils.LogPortMetrics(t, otg, args.topo)
	otgutils.LogFlowMetrics(t, otg, args.topo)

	for _, flow := range flows {
		outPkts := float32(gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).Counters().OutPkts().State()))
		inPkts := float32(gnmi.Get(t, otg, gnmi.OTG().Flow(flow.Name()).Counters().InPkts().State()))

		if outPkts == 0 {
			t.Fatalf("OutPkts for flow %s is 0, want > 0", flow)
		}
		if match {
			if got := ((outPkts - inPkts) * 100) / outPkts; got > 0 {
				t.Fatalf("LossPct for flow %s: got %v, want 0", flow.Name(), got)
			}
		} else {
			if got := ((outPkts - inPkts) * 100) / outPkts; got != 100 {
				t.Fatalf("LossPct for flow %s: got %v, want 100", flow.Name(), got)
			}
		}

	}
}

// validateTunnelEncapRatio checks whether tunnel1 and tunnel2 ecapped packets are withing specific ratio
func validateTunnelEncapRatio(t *testing.T, tunCounter map[string][]int) {
	for port, counter := range tunCounter {
		t.Logf("Validating tunnel encap ratio for %s", port)
		tunnel1Pkts := float32(counter[0])
		tunnel2Pkts := float32(counter[1])
		if tunnel1Pkts == 0 {
			t.Error("tunnel1 encapped packet count: got 0, want > 0")
		} else if tunnel2Pkts == 0 {
			t.Error("tunnel2 encapped packet count: got 0, want > 0")
		} else {
			totalPkts := tunnel1Pkts + tunnel2Pkts
			if (tunnel1Pkts/totalPkts) < (ratioTunEncap1-ratioTunEncapTol) ||
				(tunnel1Pkts/totalPkts) > (ratioTunEncap1+ratioTunEncapTol) {
				t.Errorf("tunnel1 encapsulation ratio (%f) is not within range", tunnel1Pkts/totalPkts)
			} else if (tunnel2Pkts/totalPkts) < (ratioTunEncap2-ratioTunEncapTol) ||
				(tunnel2Pkts/totalPkts) > (ratioTunEncap2+ratioTunEncapTol) {
				t.Errorf("tunnel2 encapsulation ratio (%f) is not within range", tunnel1Pkts/totalPkts)
			} else {
				t.Log("tunnel encapsulated packets are within ratio")
			}
		}
	}
}

// validatePacketCapture reads capture files and checks the encapped packet for desired protocol, dscp and ttl
func validatePacketCapture(t *testing.T, args *testArgs, otgPortNames []string, pa *packetAttr) map[string][]int {
	tunCounter := make(map[string][]int)
	for _, otgPortName := range otgPortNames {
		bytes := args.ate.OTG().GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(otgPortName))
		f, err := os.CreateTemp("", ".pcap")
		if err != nil {
			t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
		}
		if _, err := f.Write(bytes); err != nil {
			t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
		}
		f.Close()
		t.Logf("Verifying packet attributes captured on %s", otgPortName)
		handle, err := pcap.OpenOffline(f.Name())
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		tunnel1Pkts := 0
		tunnel2Pkts := 0
		for packet := range packetSource.Packets() {
			ipV4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipV4Layer != nil {
				v4Packet, _ := ipV4Layer.(*layers.IPv4)
				if got := v4Packet.Protocol; got != layers.IPProtocol(pa.protocol) {
					t.Errorf("Packet protocol type mismatch, got: %d, want %d", got, pa.protocol)
					break
				}
				if got := int(v4Packet.TOS >> 2); got != pa.dscp {
					t.Errorf("Dscp value mismatch, got %d, want %d", got, pa.dscp)
					break
				}
				if got := uint32(v4Packet.TTL); got != pa.ttl {
					t.Errorf("TTL mismatch, got: %d, want: %d", got, pa.ttl)
					break
				}
				if v4Packet.DstIP.String() == tunnelDstIP1 {
					tunnel1Pkts++
				}
				if v4Packet.DstIP.String() == tunnelDstIP2 {
					tunnel2Pkts++
				}

			}
		}
		t.Logf("tunnel1, tunnel2 packet count on %s: %d , %d", otgPortName, tunnel1Pkts, tunnel2Pkts)
		tunCounter[otgPortName] = []int{tunnel1Pkts, tunnel2Pkts}
	}
	return tunCounter

}

// startCapture starts the capture on the otg ports
func startCapture(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, cs)
}

// stopCapture starts the capture on the otg ports
func stopCapture(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.STOP)
	otg.SetControlState(t, cs)
}

// normalize normalizes the input values so that the output values sum
// to 1.0 but reflect the proportions of the input.  For example,
// input [1, 2, 3, 4] is normalized to [0.1, 0.2, 0.3, 0.4].
func normalize(xs []uint64) (ys []float64, sum uint64) {
	for _, x := range xs {
		sum += x
	}
	ys = make([]float64, len(xs))
	for i, x := range xs {
		ys[i] = float64(x) / float64(sum)
	}
	return ys, sum
}

// validateTrafficDistribution checks if the packets received on receiving ports are within specificied weight ratios
func validateTrafficDistribution(t *testing.T, ate *ondatra.ATEDevice, wantWeights []float64) {
	inFramesAllPorts := gnmi.GetAll(t, ate.OTG(), gnmi.OTG().PortAny().Counters().InFrames().State())
	// skip first entry that belongs to source port on ate
	gotWeights, _ := normalize(inFramesAllPorts[1:])

	t.Log("got ratio:", gotWeights)
	t.Log("want ratio:", wantWeights)
	if diff := cmp.Diff(wantWeights, gotWeights, cmpopts.EquateApprox(0, trfDistTolerance)); diff != "" {
		t.Errorf("Packet distribution ratios -want,+got:\n%s", diff)
	}
}

// configStaticArp configures static arp entries
func configStaticArp(p string, ipv4addr string, macAddr string) *oc.Interface {
	i := &oc.Interface{Name: ygot.String(p)}
	i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
	s := i.GetOrCreateSubinterface(0)
	s4 := s.GetOrCreateIpv4()
	n4 := s4.GetOrCreateNeighbor(ipv4addr)
	n4.LinkLayerAddress = ygot.String(macAddr)
	return i
}

// staticARPWithSecondaryIP configures secondary IPs and static ARP.
func staticARPWithSecondaryIP(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	p2 := dut.Port(t, "port2")
	gnmi.Update(t, dut, gnmi.OC().Interface(p2.Name()).Config(), dutPort2DummyIP.NewOCInterface(p2.Name(), dut))
	gnmi.Update(t, dut, gnmi.OC().Interface(p2.Name()).Config(), configStaticArp(p2.Name(), otgPort2DummyIP.IPv4, magicMac))
}
