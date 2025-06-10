// Copyright 2024 Google LLC
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

package mpls_in_udp_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/gribi"
	"github.com/openconfig/featureprofiles/internal/otgutils"
	"github.com/openconfig/gribigo/chk"
	"github.com/openconfig/gribigo/client"
	"github.com/openconfig/gribigo/constants"
	"github.com/openconfig/gribigo/fluent"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/gnmi/oc/networkinstance"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygot/ygot"
)

const (
	ipv4PrefixLen      = 30
	ipv6PrefixLen      = 126
	ipv6FlowIP         = "2015:aa8::1"
	trafficDuration    = 15 * time.Second
	ipv6EntryPrefix    = "2015:aa8::"
	ipv6EntryPrefixLen = 128

	nh101Index          = uint64(101)
	nhgIndex            = uint64(100)
	mplsLabel           = uint64(101)
	innerIPv6DstA       = "2001:aa:bb::1"
	innerIPv6DstAPrefix = "2001:aa:bb::1/128"
	outerIpv6Src        = "2001:f:a:1::0"
	outerIpv6DstA       = "2001:f:c:e::1"
	outerDstUDPPort     = uint16(6635)
	outerSrcUDPPort     = uint16(4500)
	outerDscp           = uint8(26)
	outerIPTTL          = uint8(64)
	flowName            = "MPLSOUDP_TestFlow"

	// COPIED from basic_encap_test.go - Missing constants for static ARP
	magicMac = "02:00:00:00:00:01"
	magicIP  = "192.0.2.254"

	// COPIED from basic_encap_test.go - Missing protocol constants
	ipipProtocol = 4
	udpProtocol  = 17
)

var (
	otgDstPorts = []string{"port2"}
	otgSrcPort  = "port1"
	// COPIED from basic_encap_test.go - Missing variable for multi-port capture support
	otgMutliPortCaptureSupported = true
	// COPIED from basic_encap_test.go - Missing weight constants
	wantWeights = []float64{1.0} // Single destination for MPLS-in-UDP
	dutPort1    = attrs.Attributes{
		Desc:    "dutPort1",
		MAC:     "02:01:00:00:00:01",
		IPv4:    "192.0.2.1",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::1",
		IPv6Len: ipv6PrefixLen,
	}
	atePort1 = attrs.Attributes{
		Name:    "port1",
		MAC:     "02:00:01:01:01:01",
		IPv4:    "192.0.2.2",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::2",
		IPv6Len: ipv6PrefixLen,
	}
	dutPort2 = attrs.Attributes{
		Desc:    "dutPort2",
		MAC:     "02:01:00:00:00:02",
		IPv4:    "192.0.2.5",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::5",
		IPv6Len: ipv6PrefixLen,
	}
	atePort2 = attrs.Attributes{
		Name:    "port2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::6",
		IPv6Len: ipv6PrefixLen,
	}
	fa6 = flowAttr{
		src:        atePort1.IPv6,
		dst:        outerIpv6DstA,
		defaultDst: ipv6FlowIP,
		srcMac:     atePort1.MAC,
		dstMac:     dutPort1.MAC,
		srcPort:    otgSrcPort,
		dstPorts:   otgDstPorts,
		topo:       gosnappi.NewConfig(),
	}
)

type flowAttr struct {
	src        string   // source IP address
	dst        string   // destination IP address
	defaultDst string   // default destination IP address
	srcPort    string   // source OTG port
	dstPorts   []string // destination OTG ports
	srcMac     string   // source MAC address
	dstMac     string   // destination MAC address
	topo       gosnappi.Config
}

type packetResult struct {
	mplsLabel  uint64
	udpSrcPort uint16
	udpDstPort uint16
	ipTTL      uint8
	srcIP      string
	dstIP      string
}

// packetAttr represents the packet attributes to be validated
// COPIED from basic_encap_test.go for compatibility
type packetAttr struct {
	protocol uint8
	dscp     int
	ttl      uint32
}

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	d := gnmi.OC()
	p1 := dut.Port(t, "port1")
	p2 := dut.Port(t, "port2")
	portList := []*ondatra.Port{p1, p2}
	dutPortAttrs := []attrs.Attributes{dutPort1, dutPort2}

	// Configure default network instance (essential for gRIBI tests)
	t.Log("Configure default network instance")
	fptest.ConfigureDefaultNetworkInstance(t, dut)

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

	// Add static ARP configuration support like basic_encap_test.go for hardware compatibility
	if deviations.GRIBIMACOverrideWithStaticARP(dut) {
		configureStaticARP(t, dut)
	} else if deviations.GRIBIMACOverrideStaticARPStaticRoute(dut) {
		configureStaticARPWithRoute(t, dut)
	}
}

// configStaticArp configures static arp entries
// COPIED EXACTLY from basic_encap_test.go
func configStaticArp(p string, ipv4addr string, macAddr string) *oc.Interface {
	i := &oc.Interface{Name: ygot.String(p)}
	i.Type = oc.IETFInterfaces_InterfaceType_ethernetCsmacd
	s := i.GetOrCreateSubinterface(0)
	s4 := s.GetOrCreateIpv4()
	n4 := s4.GetOrCreateNeighbor(ipv4addr)
	n4.LinkLayerAddress = ygot.String(macAddr)
	return i
}

// staticARPWithMagicUniversalIP configures static ARP with magic universal IP
// COPIED EXACTLY from basic_encap_test.go
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

// staticARPWithSecondaryIP configures secondary IPs and static ARP
// COPIED from basic_encap_test.go and adapted for MPLS-in-UDP (2 ports instead of 4)
func staticARPWithSecondaryIP(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	p2 := dut.Port(t, "port2")
	gnmi.Update(t, dut, gnmi.OC().Interface(p2.Name()).Config(), configStaticArp(p2.Name(), atePort2.IPv4, magicMac))
}

// configureStaticARP configures static ARP entries for hardware compatibility
func configureStaticARP(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	t.Log("Configuring static ARP entries for hardware compatibility")
	staticARPWithSecondaryIP(t, dut)
}

// configureStaticARPWithRoute configures static ARP with static route for hardware compatibility
func configureStaticARPWithRoute(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	t.Log("Configuring static ARP with static route for hardware compatibility")
	staticARPWithMagicUniversalIP(t, dut)
}

// programBaseEntries pushes base routing entries required for MPLS-in-UDP functionality
// COPIED EXACTLY from basic_encap_test.go programEntries function pattern (using old gRIBI API)
func programBaseEntries(t *testing.T, dut *ondatra.DUTDevice, c *gribi.Client) {
	t.Helper()
	t.Log("Programming base routing entries for MPLS-in-UDP test")

	// Add basic next hop for port2 (destination port) - using old gRIBI API like basic_encap_test.go
	if deviations.GRIBIMACOverrideWithStaticARP(dut) {
		c.AddNH(t, 1, "MACwithIp", deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB, &gribi.NHOptions{Dest: atePort2.IPv4, Mac: magicMac})
	} else if deviations.GRIBIMACOverrideStaticARPStaticRoute(dut) {
		c.AddNH(t, 1, "MACwithIp", deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB, &gribi.NHOptions{Dest: magicIP, Mac: magicMac})
	} else {
		// FIXED: Use magicMac instead of atePort2.MAC for hardware compatibility (like basic_encap_test.go)
		c.AddNH(t, 1, "MACwithInterface", deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB, &gribi.NHOptions{Interface: dut.Port(t, "port2").Name(), Mac: magicMac})
	}

	// Add next hop group - using old gRIBI API like basic_encap_test.go
	c.AddNHG(t, 1, map[uint64]uint64{1: 1}, deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)

	// Add IPv6 route for basic connectivity - using old gRIBI API like basic_encap_test.go
	c.AddIPv6(t, ipv6FlowIP+"/128", 1, deviations.DefaultNetworkInstance(dut), deviations.DefaultNetworkInstance(dut), fluent.InstalledInFIB)
}

// cleanupBaseEntries removes base routing entries
// SIMPLIFIED: Using c.FlushAll() like basic_encap_test.go (base entries will be cleaned up automatically)
func cleanupBaseEntries(t *testing.T, dut *ondatra.DUTDevice, c *gribi.Client) {
	t.Helper()
	t.Log("Base routing entries will be cleaned up by c.FlushAll() in defer")
	// No explicit cleanup needed - c.FlushAll() in main function will handle this
}

// configureOTG configures port1 on the OTG and returns the configuration.
func configureOTG(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	topo := gosnappi.NewConfig()
	t.Logf("Configuring OTG port1 & port2")
	p1 := ate.Port(t, "port1")
	p2 := ate.Port(t, "port2")

	atePort1.AddToOTG(topo, p1, &dutPort1)
	atePort2.AddToOTG(topo, p2, &dutPort2)

	var pmd100GFRPorts []string
	for _, p := range topo.Ports().Items() {
		port := ate.Port(t, p.Name())
		if port.PMD() == ondatra.PMD100GBASELR4 {
			pmd100GFRPorts = append(pmd100GFRPorts, port.ID())
		}
	}
	// Disable FEC for 100G-FR ports because Novus does not support it.
	if len(pmd100GFRPorts) > 0 {
		l1Settings := topo.Layer1().Add().SetName("L1").SetPortNames(pmd100GFRPorts)
		l1Settings.SetAutoNegotiate(true).SetIeeeMediaDefaults(false).SetSpeed("speed_100_gbps")
		autoNegotiate := l1Settings.AutoNegotiation()
		autoNegotiate.SetRsFec(false)
	}

	t.Logf("Pushing config to ATE and starting protocols...")
	otg := ate.OTG()
	otg.PushConfig(t, topo)
	t.Logf("starting protocols...")
	otg.StartProtocols(t)
	time.Sleep(50 * time.Second) // Match basic_encap_test.go timing (50 seconds vs 30)
	otgutils.WaitForARP(t, otg, topo, "IPv4")
	otgutils.WaitForARP(t, otg, topo, "IPv6")
	return topo
}

// getFlow returns a flow of ipv6.
func (fa *flowAttr) getFlow(flowType string, name string) gosnappi.Flow {
	flow := fa.topo.Flows().Add().SetName(name)
	flow.Metrics().SetEnable(true)

	flow.TxRx().Port().SetTxName(fa.srcPort).SetRxNames(fa.dstPorts)
	e1 := flow.Packet().Add().Ethernet()
	e1.Src().SetValue(fa.srcMac)
	e1.Dst().SetValue(fa.dstMac)
	if flowType == "ipv6" {
		v6 := flow.Packet().Add().Ipv6()
		v6.Src().SetValue(fa.src)
		switch name {
		case "ip6a1":
			v6.Dst().SetValue(fa.dst)
		case "ip6a2":
			v6.Dst().SetValue(fa.defaultDst)
		default:
			v6.Dst().SetValue(fa.dst)
		}
	}
	return flow
}

// enableCapture enables packet capture on specified list of ports on OTG
// COPIED EXACTLY from basic_encap_test.go (working implementation)
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
// COPIED EXACTLY from basic_encap_test.go (working implementation)
func clearCapture(t *testing.T, otg *otg.OTG, topo gosnappi.Config) {
	t.Log("Clearing capture")
	topo.Captures().Clear()
	otg.PushConfig(t, topo)
}

// startCapture starts the capture on the otg ports
// COPIED EXACTLY from basic_encap_test.go (working implementation)
func startCapture(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, cs)
}

// stopCapture stops the capture on the otg ports
// COPIED EXACTLY from basic_encap_test.go (working implementation)
func stopCapture(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.STOP)
	otg.SetControlState(t, cs)
}

// sendTraffic starts traffic flows and send traffic for a fixed duration
// FIXED: Preserve capture configuration when pushing config (critical fix for capture issue)
func sendTraffic(t *testing.T, args *testArgs, flows []gosnappi.Flow, capture bool) {
	otg := args.ate.OTG()

	// CRITICAL FIX: Preserve existing capture configuration before modifying flows
	existingCaptures := make([]gosnappi.Capture, 0)
	for _, captureItem := range args.topo.Captures().Items() {
		existingCaptures = append(existingCaptures, captureItem)
	}

	args.topo.Flows().Clear().Items()
	args.topo.Flows().Append(flows...)

	// CRITICAL FIX: Restore capture configuration before pushing config
	if len(existingCaptures) > 0 {
		t.Logf("Preserving %d existing capture configurations during traffic setup", len(existingCaptures))
		args.topo.Captures().Clear()
		for _, capture := range existingCaptures {
			args.topo.Captures().Append(capture)
		}
		// Verify capture configuration is preserved
		pb, _ := args.topo.Marshal().ToProto()
		t.Logf("Capture configuration after restoration: %v", pb.GetCaptures())
	}

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

// testArgs structure to match basic_encap_test.go pattern
type testArgs struct {
	dut    *ondatra.DUTDevice
	ate    *ondatra.ATEDevice
	topo   gosnappi.Config
	client *gribi.Client
}

// testTrafficv6 generates traffic flow from source network to
// destination network via srcEndPoint to dstEndPoint and checks for
// packet loss and returns loss percentage as float.
// REFACTORED to use the working sendTraffic pattern from basic_encap_test.go
func testTrafficv6(t *testing.T, args *testArgs, srcEndPoint, dstEndPoint attrs.Attributes, startAddress string, dur time.Duration) float32 {
	// Create flow using the same pattern as basic_encap_test.go
	flow := args.topo.Flows().Add().SetName(flowName)
	flow.Metrics().SetEnable(true)
	flow.TxRx().Port().
		SetTxName(srcEndPoint.Name).
		SetRxNames([]string{dstEndPoint.Name})
	flow.Duration().Continuous()
	flow.Packet().Add().Ethernet()
	v6 := flow.Packet().Add().Ipv6()
	v6.Src().SetValue(srcEndPoint.IPv6)
	v6.Dst().Increment().SetStart(startAddress).SetCount(24)

	// Use sendTraffic function (working pattern from basic_encap_test.go)
	sendTraffic(t, args, []gosnappi.Flow{flow}, false)

	time.Sleep(5 * time.Second)

	txPkts := gnmi.Get(t, args.ate.OTG(), gnmi.OTG().Flow(flowName).Counters().OutPkts().State())
	rxPkts := gnmi.Get(t, args.ate.OTG(), gnmi.OTG().Flow(flowName).Counters().InPkts().State())
	lossPct := (txPkts - rxPkts) * 100 / txPkts
	return float32(lossPct)
}

func formatMPLSHeader(data []byte) string {
	if len(data) < 4 {
		return ""
	}

	headerValue := binary.BigEndian.Uint32(data[:4])

	label := (headerValue >> 12) & 0xFFFFF
	exp := uint8((headerValue >> 9) & 0x07)
	s := (headerValue >> 8) & 0x01
	ttl := uint8(headerValue & 0xFF)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("MPLS Label: %d\n", label))
	sb.WriteString(fmt.Sprintf("EXP: %d\n", exp))
	sb.WriteString(fmt.Sprintf("Bottom of Stack: %t\n", s == 1))
	sb.WriteString(fmt.Sprintf("TTL: %d\n", ttl))

	if len(data) > 4 {
		sb.WriteString(fmt.Sprintf("Payload: % X", data[4:]))
	}

	return sb.String()
}

func checkEncapHeaders(t *testing.T, dut *ondatra.DUTDevice, nhgPaths []*networkinstance.NetworkInstance_Afts_NextHopGroupPath, wantEncapHeaders map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader) {
	for _, p := range nhgPaths {
		nhg, present := gnmi.Lookup(t, dut, p.State()).Val()
		if !present {
			return
		}
		nhs := nhg.NextHop
		for ind := range nhs {
			nhp := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHop(ind)
			nh, present := gnmi.Lookup(t, dut, nhp.State()).Val()
			if !present {
				continue
			}
			ehs := nh.EncapHeader
			for i, eh := range ehs {
				if diff := cmp.Diff(eh, wantEncapHeaders[i]); diff != "" {
					t.Errorf("Diff (-got +want): %v", diff)
				}
			}
		}
	}
}

func mplsLabelToPacketBytes(n uint32) []byte {
	buf := make([]byte, 4)
	n <<= 12
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// validatePacketCapture reads capture files and checks the encapped packet for desired protocol, dscp and ttl
// ENHANCED with better error handling and debugging like basic_encap_test.go
func validatePacketCapture(t *testing.T, ate *ondatra.ATEDevice, otgPortName string, pr *packetResult) {
	t.Logf("Verifying packet attributes captured on %s", otgPortName)
	packetBytes := ate.OTG().GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(otgPortName))

	// CRITICAL: Check if we actually got any capture data
	if len(packetBytes) == 0 {
		t.Fatalf("ERROR: No capture data received from port %s - capture may not be working", otgPortName)
	}
	t.Logf("Received %d bytes of capture data from port %s", len(packetBytes), otgPortName)

	f, err := os.CreateTemp("", ".pcap")
	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	if _, err := f.Write(packetBytes); err != nil {
		t.Fatalf("ERROR: Could not write packetBytes to pcap file: %v\n", err)
	}
	f.Close()

	handle, err := pcap.OpenOffline(f.Name())
	if err != nil {
		t.Fatalf("ERROR: Could not open pcap file: %v", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetCount := 0
	for packet := range packetSource.Packets() {
		packetCount++
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if udpLayer == nil || ipv6Layer == nil {
			t.Logf("Packet %d: Skipping non-UDP/IPv6 packet", packetCount)
			continue
		}

		t.Logf("Packet %d: Found UDP/IPv6 packet, validating...", packetCount)

		// Ipv6 packet checks
		v6Packet := ipv6Layer.(*layers.IPv6)
		// Validate destination IP is dstIP
		if v6Packet.DstIP.String() != pr.dstIP {
			t.Errorf("Got packet destination IP %s, want %s", v6Packet.DstIP.String(), pr.dstIP)
		}
		if v6Packet.SrcIP.String() != pr.srcIP {
			t.Errorf("Got packet source IP %s, want %s", v6Packet.SrcIP.String(), pr.srcIP)
		}
		if v6Packet.HopLimit != outerIPTTL-1 {
			t.Errorf("Got hop limit %d, want %d", v6Packet.HopLimit, outerIPTTL-1)
		}

		// UDP packet checks
		udpPacket := udpLayer.(*layers.UDP)
		if udpPacket.SrcPort != layers.UDPPort(pr.udpSrcPort) {
			t.Errorf("Got udp source port: %d, want %d", udpPacket.SrcPort, pr.udpSrcPort)
		}
		if udpPacket.DstPort != layers.UDPPort(pr.udpDstPort) {
			t.Errorf("Got udp source port: %d, want %d", udpPacket.DstPort, pr.udpDstPort)
		}

		mplsBytes := mplsLabelToPacketBytes(uint32(pr.mplsLabel))
		payload := udpLayer.(*layers.UDP).LayerPayload()
		if !bytes.Equal(payload, mplsBytes) {
			t.Errorf("Got UDP payload %s, want %s", formatMPLSHeader(payload), formatMPLSHeader(mplsBytes))
		}

		t.Logf("Packet %d: Validation successful", packetCount)
		return // Found and validated at least one packet
	}

	if packetCount == 0 {
		t.Fatalf("ERROR: No packets found in capture file - traffic may not be flowing through capture port %s", otgPortName)
	}
}

// validateTrafficFlows verifies that the flow on ATE should pass for good flow and fail for bad flow
// COPIED EXACTLY from basic_encap_test.go
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

// validateTrafficDistribution validates traffic distribution (simplified for MPLS-in-UDP)
// ADAPTED from basic_encap_test.go for single destination
func validateTrafficDistribution(t *testing.T, ate *ondatra.ATEDevice, weights []float64) {
	// For MPLS-in-UDP test, we only have one destination, so just log the metrics
	otgutils.LogPortMetrics(t, ate.OTG(), ate.OTG().FetchConfig(t))
	otgutils.LogFlowMetrics(t, ate.OTG(), ate.OTG().FetchConfig(t))
}

// testCounters test packet counters and should be called after testTraffic
func testCounters(t *testing.T, dut *ondatra.DUTDevice, wantTxPkts, wantRxPkts uint64) {
	got := gnmi.Get(t, dut, gnmi.OC().Interface(dut.Port(t, "port1").Name()).Counters().InPkts().State())
	t.Logf("DUT port 1 in-pkts: %d", got)
	if got < wantTxPkts {
		t.Errorf("DUT got less packets (%d) than OTG sent (%d)", got, wantTxPkts)
	}

	got = gnmi.Get(t, dut, gnmi.OC().Interface(dut.Port(t, "port2").Name()).Counters().OutPkts().State())
	t.Logf("DUT port 2 out-pkts: %d", got)
	if got < wantRxPkts {
		t.Errorf("DUT got sent less packets (%d) than OTG received (%d)", got, wantRxPkts)
	}
}

// Tests TE-18.1.1
func TestMPLSOUDPEncap(t *testing.T) {
	// Configure DUT
	dut := ondatra.DUT(t, "dut")
	configureDUT(t, dut)

	// Configure ATE (includes protocol startup and ARP wait)
	ate := ondatra.ATE(t, "ate")
	topo := configureOTG(t, ate)
	otg := ate.OTG()

	// configure gRIBI client (like basic_encap_test.go)
	c := gribi.Client{
		DUT:         dut,
		FIBACK:      true,
		Persistence: true,
	}

	if err := c.Start(t); err != nil {
		t.Fatalf("gRIBI Connection can not be established")
	}

	defer c.Close(t)
	// flush all AFT entries after test
	defer c.FlushAll(t)
	c.BecomeLeader(t)

	// flush all existing AFT entries on the router
	c.FlushAll(t)

	// CRITICAL: Program base routing entries (like basic_encap_test.go)
	programBaseEntries(t, dut, &c)
	// Ensure base entries are cleaned up after all tests
	defer cleanupBaseEntries(t, dut, &c)

	// Create testArgs structure to match basic_encap_test.go pattern
	tcArgs := &testArgs{
		dut:    dut,
		ate:    ate,
		topo:   topo,
		client: &c,
	}

	// Log interface configuration for debugging
	for _, d := range topo.Devices().Items() {
		eth := d.Ethernets().Items()[0]
		t.Logf("Device: %s, Interface: %s", d.Name(), eth.Name())
		if len(eth.Ipv6Addresses().Items()) > 0 {
			ipv6 := eth.Ipv6Addresses().Items()[0]
			t.Logf("  IPv6: %s/%d, Gateway: %s", ipv6.Address(), ipv6.Prefix(), ipv6.Gateway())
		}
	}

	tests := []struct {
		desc                    string
		entries                 []fluent.GRIBIEntry
		nextHopGroupPaths       []*networkinstance.NetworkInstance_Afts_NextHopGroupPath
		wantAddOperationResults []*client.OpResult
		wantAddEncapHeaders     map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader
		wantDelOperationResults []*client.OpResult
		wantDelEncapHeaders     map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader
		capturePort             string
		flowInnerDstIP          string
		wantMPLSLabel           uint64
		wantOuterDstIP          string
		wantOuterSrcIP          string
		wantOuterDstUDPPort     uint16
		wantOuterIPTTL          uint8
	}{
		{
			desc: "TE-18.1.1 MPLS-in-UDP-in-IPv6 Encap for inner IPv6 dst A",
			entries: []fluent.GRIBIEntry{
				fluent.NextHopEntry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithIndex(nh101Index).
					AddEncapHeader(
						fluent.MPLSEncapHeader().WithLabels(mplsLabel),
						fluent.UDPV6EncapHeader().
							WithSrcIP(outerIpv6Src).
							WithDstIP(outerIpv6DstA).
							WithSrcUDPPort(uint64(outerSrcUDPPort)).
							WithDstUDPPort(uint64(outerDstUDPPort)).
							WithIPTTL(uint64(outerIPTTL)).
							WithDSCP(uint64(outerDscp)),
					),
				fluent.NextHopGroupEntry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithID(nhgIndex).
					AddNextHop(nh101Index, 1),
				fluent.IPv6Entry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithPrefix(innerIPv6DstAPrefix).
					WithNextHopGroup(nhgIndex).
					WithNextHopGroupNetworkInstance(deviations.DefaultNetworkInstance(dut)), // NHG is in Default NI
			},
			nextHopGroupPaths: []*networkinstance.NetworkInstance_Afts_NextHopGroupPath{
				(*networkinstance.NetworkInstance_Afts_NextHopGroupPath)(gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Afts().NextHopGroup(nhgIndex)),
			},
			wantAddOperationResults: []*client.OpResult{
				fluent.OperationResult().
					WithNextHopOperation(nh101Index).
					WithProgrammingResult(fluent.InstalledInFIB).
					WithOperationType(constants.Add).
					AsResult(),
				fluent.OperationResult().
					WithNextHopGroupOperation(nhgIndex).
					WithProgrammingResult(fluent.InstalledInFIB).
					WithOperationType(constants.Add).
					AsResult(),
				fluent.OperationResult(). // Inlined routeInstallResult logic for IPv6
								WithIPv6Operation(innerIPv6DstAPrefix).
								WithProgrammingResult(fluent.InstalledInFIB).
								WithOperationType(constants.Add).
								AsResult(),
			},
			wantAddEncapHeaders: map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader{
				1: { // Index for MPLS header
					Index: ygot.Uint8(1),
					Type:  oc.Aft_EncapsulationHeaderType_MPLS,
					Mpls: &oc.NetworkInstance_Afts_NextHop_EncapHeader_Mpls{
						MplsLabelStack: []oc.NetworkInstance_Afts_NextHop_EncapHeader_Mpls_MplsLabelStack_Union{
							oc.UnionUint32(mplsLabel),
						},
					},
				},
				2: { // Index for UDPv6 header
					Index: ygot.Uint8(2),
					Type:  oc.Aft_EncapsulationHeaderType_UDPV6,
					UdpV6: &oc.NetworkInstance_Afts_NextHop_EncapHeader_UdpV6{
						SrcIp:      ygot.String(outerIpv6Src),
						DstIp:      ygot.String(outerIpv6DstA),
						SrcUdpPort: ygot.Uint16(outerSrcUDPPort),
						DstUdpPort: ygot.Uint16(outerDstUDPPort),
						IpTtl:      ygot.Uint8(outerIPTTL),
						Dscp:       ygot.Uint8(outerDscp),
					},
				},
			},
			wantDelOperationResults: []*client.OpResult{
				fluent.OperationResult().
					WithIPv6Operation(innerIPv6DstAPrefix).
					WithProgrammingResult(fluent.InstalledInFIB).
					WithOperationType(constants.Delete).
					AsResult(),
				fluent.OperationResult().
					WithNextHopGroupOperation(nhgIndex).
					WithProgrammingResult(fluent.InstalledInFIB).
					WithOperationType(constants.Delete).
					AsResult(),
				fluent.OperationResult().
					WithNextHopOperation(nh101Index).
					WithProgrammingResult(fluent.InstalledInFIB).
					WithOperationType(constants.Delete).
					AsResult(),
			},
			wantDelEncapHeaders: map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader{},
			capturePort:         atePort2.Name, // "port2"
			flowInnerDstIP:      strings.Split(innerIPv6DstAPrefix, "/")[0],
			wantMPLSLabel:       mplsLabel,
			wantOuterDstIP:      outerIpv6DstA,
			wantOuterSrcIP:      outerIpv6Src,
			wantOuterDstUDPPort: outerDstUDPPort,
			wantOuterIPTTL:      outerIPTTL - 1, // Expected TTL after DUT processing
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Use the existing gRIBI client (like basic_encap_test.go)
			c.AddEntries(t, tc.entries, tc.wantAddOperationResults)

			// Create flow for traffic generation
			flow := topo.Flows().Add().SetName(flowName)
			flow.Metrics().SetEnable(true)
			flow.TxRx().Port().
				SetTxName(atePort1.Name).
				SetRxNames([]string{atePort2.Name})
			flow.Duration().Continuous()
			flow.Packet().Add().Ethernet()
			v6 := flow.Packet().Add().Ipv6()
			v6.Src().SetValue(atePort1.IPv6)
			v6.Dst().Increment().SetStart(tc.flowInnerDstIP).SetCount(24)

			// REFACTORED: Follow basic_encap_test.go capture pattern EXACTLY
			if otgMutliPortCaptureSupported {
				enableCapture(t, otg, topo, []string{tc.capturePort})
				t.Log("Start capture and send traffic")
				sendTraffic(t, tcArgs, []gosnappi.Flow{flow}, true)
				t.Log("Validate captured packet attributes")
				validatePacketCapture(t, ate, tc.capturePort,
					&packetResult{
						mplsLabel:  tc.wantMPLSLabel,
						udpSrcPort: outerSrcUDPPort,
						udpDstPort: tc.wantOuterDstUDPPort,
						ipTTL:      tc.wantOuterIPTTL,
						srcIP:      tc.wantOuterSrcIP,
						dstIP:      tc.wantOuterDstIP,
					})
				clearCapture(t, otg, topo)
			} else {
				enableCapture(t, otg, topo, []string{tc.capturePort})
				t.Log("Start capture and send traffic")
				sendTraffic(t, tcArgs, []gosnappi.Flow{flow}, true)
				t.Log("Validate captured packet attributes")
				validatePacketCapture(t, ate, tc.capturePort,
					&packetResult{
						mplsLabel:  tc.wantMPLSLabel,
						udpSrcPort: outerSrcUDPPort,
						udpDstPort: tc.wantOuterDstUDPPort,
						ipTTL:      tc.wantOuterIPTTL,
						srcIP:      tc.wantOuterSrcIP,
						dstIP:      tc.wantOuterDstIP,
					})
				clearCapture(t, otg, topo)
			}

			t.Log("Validate traffic flows")
			validateTrafficFlows(t, tcArgs, []gosnappi.Flow{flow}, false, true)
			t.Log("Validate traffic distribution")
			validateTrafficDistribution(t, ate, wantWeights)

			checkEncapHeaders(t, dut, tc.nextHopGroupPaths, tc.wantAddEncapHeaders)

			// Clean up test-specific entries
			slices.Reverse(tc.entries)
			c.DeleteEntries(t, tc.entries, tc.wantDelOperationResults)

			// Test traffic after deletion (should have 100% loss)
			if loss := testTrafficv6(t, tcArgs, atePort1, atePort2, tc.flowInnerDstIP, 5*time.Second); loss != 100 {
				t.Errorf("Loss: got %g, want 100", loss)
			}

			checkEncapHeaders(t, dut, tc.nextHopGroupPaths, tc.wantDelEncapHeaders)
		})
	}

	// Final cleanup: Ensure we leave the system in a clean state
	t.Log("Final cleanup: clearing all captures")
	clearCapture(t, otg, topo)
}
