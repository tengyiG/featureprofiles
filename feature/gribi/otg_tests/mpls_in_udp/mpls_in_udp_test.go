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
	"context"
	"encoding/binary"
	"fmt"
	"os"
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
	"github.com/openconfig/gribigo/fluent"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygot/ygot"
)

const (
	ipv6PrefixLen      = 126
	ipv6FlowIP         = "2015:aa8::1"
	trafficDuration    = 15 * time.Second
	nhg10ID            = 10
	vrfEncapA          = "ENCAP_TE_VRF_A"
	ipv6EntryPrefix    = "2015:aa8::"
	ipv6EntryPrefixLen = 128
	nh201ID            = 201
	nhgName            = "nh-group-1"
	outerDstUDPPort    = "6635"
	outerDscp          = "26"
	outerIPTTL         = "64"

	// Constants for gRIBI programming - Path A (matches README NH#101/NHG#100)
	nhIndexA         = 101
	nhgIndexA        = 100
	mplsLabelA       = uint64(101)
	outerIpv6DstA    = "2001:f:c:e::1"
	ateDstNetCIDRv6A = "2001:aa:bb::1/128"
	ateDstNetCIDRv4A = "10.5.1.1/32"

	// Constants for gRIBI programming - Path B (matches README NH#201/NHG#200)
	nhIndexB         = 201
	nhgIndexB        = 200
	mplsLabelB       = uint64(201)
	outerIpv6DstB    = "2001:f:c:e::2"
	ateDstNetCIDRv6B = "2001:aa:bb::2/128"
	ateDstNetCIDRv4B = "10.5.1.2/32"

	// Common constants from README
	outerIpv6Src        = "2001:f:a:1::0"
	udpSrcPort          = uint16(6635)
	udpDstPort   uint16 = 6635
	ipTTL        uint8  = 64
	dscp         uint8  = 26

	flowNameA = "FlowA" // Traffic targeting ateDstNetCIDRv6A
	flowNameB = "FlowB" // Traffic targeting ateDstNetCIDRv6B
	// Destination start IPs for flows (use the specific /128 addresses from constants)
	dstIPStartA = "2001:aa:bb::1"
	dstIPStartB = "2001:aa:bb::2"
	dstIPCount  = 1 // Send to the single specific address
)

var (
	otgDstPorts = []string{"port2"}
	otgSrcPort  = "port1"
	dutPort1    = attrs.Attributes{
		Desc:    "dutPort1",
		MAC:     "02:01:00:00:00:01",
		IPv6:    "2001:f:d:e::1",
		IPv6Len: ipv6PrefixLen,
	}
	otgPort1 = attrs.Attributes{
		Name:    "otgPort1",
		MAC:     "02:00:01:01:01:01",
		IPv6:    "2001:f:d:e::2",
		IPv6Len: ipv6PrefixLen,
	}
	dutPort2 = attrs.Attributes{
		Desc:    "dutPort2",
		MAC:     "02:01:00:00:00:02",
		IPv6:    "2001:f:d:e::5",
		IPv6Len: ipv6PrefixLen,
	}
	otgPort2 = attrs.Attributes{
		Name:    "otgPort2",
		MAC:     "02:00:02:01:01:01",
		IPv6:    "2001:f:d:e::6",
		IPv6Len: ipv6PrefixLen,
	}
	fa6 = flowAttr{
		src:        otgPort1.IPv6,
		dst:        outerIpv6DstA,
		defaultDst: ipv6FlowIP,
		srcMac:     otgPort1.MAC,
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

func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	d := gnmi.OC()
	p1 := dut.Port(t, "port1")
	p2 := dut.Port(t, "port2")
	portList := []*ondatra.Port{p1, p2}
	attrsList := []attrs.Attributes{dutPort1, dutPort2}

	for idx, a := range attrsList {
		p := portList[idx]
		intf := a.NewOCInterface(p.Name(), dut)
		if p.PMD() == ondatra.PMD100GBASEFR && dut.Vendor() == ondatra.ARISTA {
			e := intf.GetOrCreateEthernet()
			e.AutoNegotiate = ygot.Bool(false)
			e.DuplexMode = oc.Ethernet_DuplexMode_FULL
			e.PortSpeed = oc.IfEthernet_ETHERNET_SPEED_SPEED_100GB
		}
		if deviations.InterfaceEnabled(dut) {
			s := intf.GetOrCreateSubinterface(0)
			s4 := s.GetOrCreateIpv4()
			s4.Enabled = ygot.Bool(true)
		}

		gnmi.Replace(t, dut, d.Interface(p.Name()).Config(), intf)
	}

	for idx, a := range attrsList {
		p := portList[idx]
		gnmi.Await(t, dut, d.Interface(p.Name()).Subinterface(0).Ipv6().Address(a.IPv6).Ip().State(), time.Minute, a.IPv6)
	}
}

// configureOTG configures port1 on the OTG.
func configureOTG(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	otg := ate.OTG()
	topo := gosnappi.NewConfig()
	t.Logf("Configuring OTG port1 & port2")
	p1 := ate.Port(t, "port1")
	p2 := ate.Port(t, "port2")

	otgPort1.AddToOTG(topo, p1, &dutPort1)
	otgPort2.AddToOTG(topo, p2, &dutPort2)

	pmd100GFRPorts := []string{}
	for _, p := range topo.Ports().Items() {
		port := ate.Port(t, p.Name())
		if port.PMD() == ondatra.PMD100GBASEFR {
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

	t.Logf("Pushing config to ATE...")
	otg.PushConfig(t, topo)
	// NOTE: Starting protocols and waiting for ARP is moved closer to traffic sending.
	return topo
}

// createFlow returns a flow definition for IPv6 traffic with a range of destination IPs.
func (fa *flowAttr) createFlow(name, dstIPStart string, dstIPCount uint32) gosnappi.Flow {
	flow := fa.topo.Flows().Add().SetName(name)
	flow.Metrics().SetEnable(true)

	flow.TxRx().Port().SetTxName(fa.srcPort).SetRxNames(fa.dstPorts)
	e1 := flow.Packet().Add().Ethernet()
	e1.Src().SetValue(fa.srcMac)
	e1.Dst().SetValue(fa.dstMac)

	v6 := flow.Packet().Add().Ipv6()
	v6.Src().SetValue(fa.src)
	// Use Increment to send to a range of destination IPs.
	v6.Dst().Increment().SetStart(dstIPStart).SetCount(dstIPCount)

	return flow
}

// clearCapture clears capture from all ports on the OTG
func clearCapture(t *testing.T, otg *otg.OTG, topo gosnappi.Config) {
	t.Log("Clearing capture")
	topo.Captures().Clear()
	otg.PushConfig(t, topo)
}

// sendTraffic starts traffic flows and send traffic for a fixed duration
func sendTraffic(t *testing.T, args *testArgs, flows []gosnappi.Flow, capture bool) {
	otg := args.ate.OTG()
	args.topo.Flows().Clear().Items()
	args.topo.Flows().Append(flows...)

	otg.PushConfig(t, args.topo)
	otg.StartProtocols(t)

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

// startCapture starts the capture on the otg ports
func startCapture(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	otg.SetControlState(t, cs)
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

// stopCapture starts the capture on the otg ports
func stopCapture(t *testing.T, ate *ondatra.ATEDevice) {
	otg := ate.OTG()
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.STOP)
	otg.SetControlState(t, cs)
}

// checkEncapHeaders verifies the programmed encapsulation headers in AFT state via gNMI.
func checkEncapHeaders(t *testing.T, dut *ondatra.DUTDevice, nhgIndex uint64, wantEncapHeaders map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader) {
	t.Helper()
	niName := deviations.DefaultNetworkInstance(dut)
	aftsPath := gnmi.OC().NetworkInstance(niName).Afts()

	nhg := gnmi.Get(t, dut, aftsPath.NextHopGroup(nhgIndex).State())
	if nhg == nil {
		t.Errorf("NextHopGroup %d not found in AFT state", nhgIndex)
		return
	}

	for _, nh := range nhg.NextHop {
		nhIndex := nh.GetIndex()
		hop := gnmi.Get(t, dut, aftsPath.NextHop(nhIndex).State())
		if hop == nil {
			t.Logf("NextHop %d not found in AFT state for NHG %d, skipping check for this NH.", nhIndex, nhgIndex)
			continue
		}
		gotEncapHeaders := make(map[uint8]*oc.NetworkInstance_Afts_NextHop_EncapHeader)
		for _, eh := range hop.EncapHeader {
			gotEncapHeaders[eh.GetIndex()] = eh
		}

		if diff := cmp.Diff(wantEncapHeaders, gotEncapHeaders); diff != "" {
			t.Errorf("checkEncapHeaders mismatch for NH %d (-want +got):\n%s", nhIndex, diff)
		} else {
			t.Logf("checkEncapHeaders successful for NH %d.", nhIndex)
		}
	}
}

// testTraffic sends the specified flows and verifies the loss percentage.
func testTraffic(t *testing.T, args *testArgs, flows []gosnappi.Flow, wantLossPercent float32) {
	t.Helper()
	sendTraffic(t, args, flows, false)

	// Verify traffic metrics
	otgutils.LogFlowMetrics(t, args.ate.OTG(), args.topo)
	for _, flow := range flows {
		flowName := flow.Name()
		txPkts := gnmi.Get(t, args.ate.OTG(), gnmi.OTG().Flow(flowName).Counters().OutPkts().State())
		rxPkts := gnmi.Get(t, args.ate.OTG(), gnmi.OTG().Flow(flowName).Counters().InPkts().State())
		lostPkts := txPkts - rxPkts
		var lossPct float32
		if txPkts == 0 {
			if rxPkts == 0 {
				lossPct = 0
				t.Logf("Flow %s: No traffic detected (Tx: 0, Rx: 0)", flowName)
			} else {
				lossPct = -1
				t.Errorf("Flow %s: Received packets without sending (Tx: 0, Rx: %d)", flowName, rxPkts)
			}
		} else {
			lossPct = float32(lostPkts*100) / float32(txPkts)
		}

		if wantLossPercent == 100 {
			if lossPct < 100 {
				t.Errorf("Flow %s: Loss percentage is %f%%, want 100%% (Tx: %d, Rx: %d)", flowName, lossPct, txPkts, rxPkts)
			} else {
				t.Logf("Flow %s: Loss percentage is %f%%, expected 100%% (Tx: %d, Rx: %d)", flowName, lossPct, txPkts, rxPkts)
			}
		} else {
			if lossPct > wantLossPercent+1.0 {
				t.Errorf("Flow %s: Loss percentage is %f%%, want <= %f%% (Tx: %d, Rx: %d)", flowName, lossPct, wantLossPercent, txPkts, rxPkts)
			} else {
				t.Logf("Flow %s: Loss percentage is %f%%, expected <= %f%% (Tx: %d, Rx: %d)", flowName, lossPct, wantLossPercent, txPkts, rxPkts)
			}
		}
	}
}

// testCounters checks DUT interface counters.
func testCounters(t *testing.T, dut *ondatra.DUTDevice, port1InPkts, port2OutPkts uint64) {
	t.Helper()
	p1Name := dut.Port(t, "port1").Name()
	p2Name := dut.Port(t, "port2").Name()

	time.Sleep(10 * time.Second)

	gotP1In := gnmi.Get(t, dut, gnmi.OC().Interface(p1Name).Counters().InPkts().State())
	t.Logf("DUT port 1 (%s) in-pkts: %d, expected >= %d", p1Name, gotP1In, port1InPkts)
	if gotP1In < port1InPkts {
		t.Errorf("DUT port 1 (%s) in-pkts: got %d, want >= %d", p1Name, gotP1In, port1InPkts)
	}

	gotP2Out := gnmi.Get(t, dut, gnmi.OC().Interface(p2Name).Counters().OutPkts().State())
	t.Logf("DUT port 2 (%s) out-pkts: %d, expected >= %d", p2Name, gotP2Out, port2OutPkts)
	if gotP2Out < port2OutPkts {
		t.Errorf("DUT port 2 (%s) out-pkts: got %d, want >= %d", p2Name, gotP2Out, port2OutPkts)
	}
}

// packetResult holds expected values for captured packets.
type packetResult struct {
	mplsLabel  uint64
	udpSrcPort uint16
	udpDstPort uint16
	ipTTL      uint8
	outerSrcIP string
	outerDstIP string
	innerSrcIP string // Source IP of the original inner packet sent by ATE
	innerDstIP string // Destination IP of the original inner packet sent by ATE
}

// formatMPLSHeader formats MPLS header bytes for logging.
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
	sb.WriteString(fmt.Sprintf("MPLS Label: %d, ", label))
	sb.WriteString(fmt.Sprintf("EXP: %d, ", exp))
	sb.WriteString(fmt.Sprintf("S: %t, ", s == 1))
	sb.WriteString(fmt.Sprintf("TTL: %d", ttl))
	if len(data) > 4 {
		sb.WriteString(fmt.Sprintf(", Payload: % X", data[4:]))
	}
	return sb.String()
}

// mplsLabelToPacketBytes converts an MPLS label to its 4-byte representation.
func mplsLabelToPacketBytes(n uint32) []byte {
	buf := make([]byte, 4)
	n <<= 12
	binary.BigEndian.PutUint32(buf, n)
	return buf
}

// validatePacketCapture validates the captured packets on the specified ATE port.
func validatePacketCapture(t *testing.T, ate *ondatra.ATEDevice, otgPortName string, wantResults []*packetResult) {
	t.Helper()
	otg := ate.OTG()
	pcapBytes := otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(otgPortName))

	// Create a temporary file to write the pcap data.
	f, err := os.CreateTemp("", "mpls-in-udp-*.pcap")
	if err != nil {
		t.Fatalf("Failed to create temp pcap file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(pcapBytes); err != nil {
		t.Fatalf("Failed to write pcap bytes to file %s: %v", f.Name(), err)
	}
	f.Close()
	t.Logf("Wrote pcap capture from port %s to %s", otgPortName, f.Name())

	// Open the pcap file for analysis.
	handle, err := pcap.OpenOffline(f.Name())
	if err != nil {
		t.Fatalf("Failed to open pcap file %s: %v", f.Name(), err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetsFound := 0
	validatedPackets := 0

	for packet := range packetSource.Packets() {
		packetsFound++
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		outerIPv6Layer := packet.Layer(layers.LayerTypeIPv6)

		if udpLayer == nil || outerIPv6Layer == nil {
			t.Logf("Packet %d: Skipping - Not an outer IPv6/UDP packet", packetsFound)
			continue
		}

		outerV6 := outerIPv6Layer.(*layers.IPv6)
		udp := udpLayer.(*layers.UDP)
		payload := udp.LayerPayload()

		// Check if this packet matches any of the expected results
		matchFound := false
		for _, want := range wantResults {
			// Check outer IPv6 header
			if outerV6.SrcIP.String() != want.outerSrcIP || outerV6.DstIP.String() != want.outerDstIP {
				continue
			}
			// Check UDP ports
			if udp.SrcPort != layers.UDPPort(want.udpSrcPort) || udp.DstPort != layers.UDPPort(want.udpDstPort) {
				continue
			}
			// Check MPLS label in payload
			wantMPLSBytes := mplsLabelToPacketBytes(uint32(want.mplsLabel))
			if !bytes.HasPrefix(payload, wantMPLSBytes) { // Check if payload starts with the MPLS header
				continue
			}

			matchFound = true
			validatedPackets++
			t.Logf("Packet %d: Validated successfully against expected result: %+v", packetsFound, want)

			if outerV6.HopLimit != want.ipTTL-1 {
				t.Errorf("Packet %d: Outer Hop Limit mismatch: got %d, want %d", packetsFound, outerV6.HopLimit, want.ipTTL-1)
			}

			break
		}
		if !matchFound {
			t.Logf("Packet %d: Did not match any expected result. OuterSrc: %s, OuterDst: %s, UDPSrc: %d, UDPDst: %d, MPLS (start): %s",
				packetsFound, outerV6.SrcIP, outerV6.DstIP, udp.SrcPort, udp.DstPort, formatMPLSHeader(payload))
		}
	}

	if packetsFound == 0 {
		t.Errorf("No packets captured on port %s", otgPortName)
	} else if validatedPackets == 0 {
		t.Errorf("No captured packets matched the expected MPLS-in-UDP structure on port %s", otgPortName)
	} else if validatedPackets < len(wantResults) {
		t.Logf("Validated %d packets, which is less than the number of expected results (%d). This might be okay depending on traffic rate.", validatedPackets, len(wantResults))
	} else {
		t.Logf("Successfully validated %d captured packets on port %s against %d expected result(s).", validatedPackets, otgPortName, len(wantResults))
	}
}

// awaitTimeout calls a fluent client Await, adding a timeout to the context.
func awaitTimeout(ctx context.Context, c *fluent.GRIBIClient, t testing.TB, timeout time.Duration) error {
	subctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Await(subctx, t)
}

// Test TE-18.1.1.
func TestMPLSOUDPEncap(t *testing.T) {
	dut := ondatra.DUT(t, "dut")
	configureDUT(t, dut)

	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	otgConfig := configureOTG(t, ate)
	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, otgConfig)
	t.Logf("starting protocols...")
	otg.StartProtocols(t)

	tests := []struct {
		desc    string
		entries []fluent.GRIBIEntry
	}{
		{
			desc: "mplsoudpv6",
			entries: []fluent.GRIBIEntry{
				// Path A: NH#101 with MPLS and UDPv6 encapsulation headers
				fluent.NextHopEntry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithIndex(nhIndexA).
					WithIPAddress(otgPort2.IPv6).
					AddEncapHeader(
						fluent.MPLSEncapHeader().WithLabels(mplsLabelA),
						fluent.UDPV6EncapHeader().
							WithSrcIP(outerIpv6Src).
							WithDstIP(outerIpv6DstA).
							WithSrcUDPPort(uint64(udpSrcPort)).
							WithDstUDPPort(uint64(udpDstPort)).
							WithIPTTL(uint64(ipTTL)).
							WithDSCP(uint64(dscp)),
					),
				fluent.NextHopGroupEntry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithID(nhgIndexA).
					AddNextHop(nhIndexA, 1),
				fluent.IPv6Entry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithPrefix(ateDstNetCIDRv6A).
					WithNextHopGroup(nhgIndexA).
					WithNextHopGroupNetworkInstance(deviations.DefaultNetworkInstance(dut)),

				// Path B: NH#201 with MPLS and UDPv6 encapsulation headers
				fluent.NextHopEntry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithIndex(nhIndexB).
					WithIPAddress(otgPort2.IPv6).
					AddEncapHeader(
						fluent.MPLSEncapHeader().WithLabels(mplsLabelB),
						fluent.UDPV6EncapHeader().
							WithSrcIP(outerIpv6Src).
							WithDstIP(outerIpv6DstB).
							WithSrcUDPPort(uint64(udpSrcPort)).
							WithDstUDPPort(uint64(udpDstPort)).
							WithIPTTL(uint64(ipTTL)).
							WithDSCP(uint64(dscp)),
					),
				fluent.NextHopGroupEntry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithID(nhgIndexB).
					AddNextHop(nhIndexB, 1),
				fluent.IPv6Entry().
					WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
					WithPrefix(ateDstNetCIDRv6B).
					WithNextHopGroup(nhgIndexB).
					WithNextHopGroupNetworkInstance(deviations.DefaultNetworkInstance(dut)),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			// Configure gRIBI client.
			gribic := dut.RawAPIs().GRIBI(t)
			c := fluent.NewClient()
			c.Connection().WithStub(gribic).
				WithRedundancyMode(fluent.ElectedPrimaryClient).
				WithPersistence().
				WithFIBACK().
				WithInitialElectionID(1, 0)
			ctx := context.Background()
			c.Start(ctx, t)
			defer c.Stop(t)
			c.StartSending(ctx, t)
			if err := awaitTimeout(ctx, c, t, time.Minute); err != nil {
				t.Fatalf("Await got error during session negotiation: %v", err)
			}

			c.Modify().AddEntry(t, tc.entries...)
			if err := awaitTimeout(ctx, c, t, time.Minute); err != nil {
				t.Fatalf("Await got error for entries: %v", err)
			}
		})
	}
}
