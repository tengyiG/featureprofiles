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
	ipv6PrefixLen      = 126
	ipv6FlowIP         = "2015:aa8::1"
	trafficDuration    = 15 * time.Second
	vrfEncapA          = "ENCAP_TE_VRF_A"
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
	atePort1 = attrs.Attributes{
		Name:    "port1",
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
	atePort2 = attrs.Attributes{
		Name:    "port2",
		MAC:     "02:00:02:01:01:01",
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

func TestMain(m *testing.M) {
	fptest.RunTests(m)
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

	for idx, a := range dutPortAttrs {
		p := portList[idx]
		gnmi.Await(t, dut, d.Interface(p.Name()).Subinterface(0).Ipv6().Address(a.IPv6).Ip().State(), time.Minute, a.IPv6)
	}
}

// configureOTG configures port1 on the OTG and returns the configuration.
func configureOTG(t *testing.T, ate *ondatra.ATEDevice) gosnappi.Config {
	topo := gosnappi.NewConfig()
	t.Logf("Configuring OTG port1 & port2")
	p1 := ate.Port(t, "port1")
	p2 := ate.Port(t, "port2")

	atePort1.AddToOTG(topo, p1, &dutPort1)
	atePort2.AddToOTG(topo, p2, &dutPort2)

	pmd100GFRPorts := []string{}
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

// enableCapture enables packet capture on a specified port on OTG.
// The topo configuration is pushed to OTG.
func enableCapture(t *testing.T, otg *otg.OTG, topo gosnappi.Config, otgPortName string) {
	t.Log("Enabling capture on port: ", otgPortName)
	topo.Captures().Clear()
	topo.Captures().Add().SetName(otgPortName).SetPortNames([]string{otgPortName}).SetFormat(gosnappi.CaptureFormat.PCAP)
	pb, _ := topo.Marshal().ToProto()
	t.Log(pb.GetCaptures())
	otg.PushConfig(t, topo)
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

// testTrafficv6 generates traffic flow from source network to
// destination network via srcEndPoint to dstEndPoint and checks for
// packet loss and returns loss percentage as float.
func testTrafficv6(t *testing.T, otg *otg.OTG, srcEndPoint, dstEndPoint attrs.Attributes, startAddress string, dur time.Duration) float32 {
	otgutils.WaitForARP(t, otg, otg.FetchConfig(t), "IPv6")
	top := otg.FetchConfig(t)
	top.Flows().Clear().Items()
	flowipv6 := top.Flows().Add().SetName(flowName)
	flowipv6.Metrics().SetEnable(true)
	flowipv6.TxRx().Device().
		SetTxNames([]string{srcEndPoint.Name + ".IPv6"}).
		SetRxNames([]string{dstEndPoint.Name + ".IPv6"})
	flowipv6.Duration().Continuous()
	flowipv6.Packet().Add().Ethernet()
	v6 := flowipv6.Packet().Add().Ipv6()
	v6.Src().SetValue(srcEndPoint.IPv6)
	v6.Dst().Increment().SetStart(startAddress).SetCount(24)
	otg.PushConfig(t, top)

	otg.StartTraffic(t)
	time.Sleep(dur)
	t.Logf("Stop traffic")
	otg.StopTraffic(t)

	time.Sleep(5 * time.Second)

	txPkts := gnmi.Get(t, otg, gnmi.OTG().Flow(flowName).Counters().OutPkts().State())
	rxPkts := gnmi.Get(t, otg, gnmi.OTG().Flow(flowName).Counters().InPkts().State())
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
func validatePacketCapture(t *testing.T, ate *ondatra.ATEDevice, otgPortName string, pr *packetResult) {
	packetBytes := ate.OTG().GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(otgPortName))
	f, err := os.CreateTemp("", ".pcap")
	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	if _, err := f.Write(packetBytes); err != nil {
		t.Fatalf("ERROR: Could not write packetBytes to pcap file: %v\n", err)
	}
	f.Close()
	t.Logf("Verifying packet attributes captured on %s", otgPortName)
	handle, err := pcap.OpenOffline(f.Name())
	if err != nil {
		t.Fatalf("ERROR: Could not open pcap file: %v", err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if udpLayer == nil || ipv6Layer == nil {
			continue
		}

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
	}
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

	// Configure ATE
	ate := ondatra.ATE(t, "ate")
	otg := ate.OTG()
	topo := configureOTG(t, ate)
	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, topo)
	t.Logf("starting protocols...")
	otg.StartProtocols(t)

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
					WithNetworkInstance(vrfEncapA). // Matching in VRF_ENCAP_A
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
			c := &gribi.Client{
				DUT:         dut,
				FIBACK:      true,
				Persistence: true,
			}

			t.Log("Starting gRIBI client...")
			if err := c.Start(t); err != nil {
				t.Fatalf("gRIBI Connection can not be established for test case %s: %v", tc.desc, err)
			}
			defer c.Close(t)
			c.BecomeLeader(t)

			t.Log("Sending ADD Modify request")
			c.AddEntries(t, tc.entries, tc.wantAddOperationResults)

			enableCapture(t, otg, topo, tc.capturePort)
			time.Sleep(1 * time.Second)
			startCapture(t, ate)
			time.Sleep(1 * time.Second)
			if loss := testTrafficv6(t, otg, atePort1, atePort2, tc.flowInnerDstIP, 5*time.Second); loss > 1 {
				t.Errorf("Loss: got %g, want <= 1", loss)
			}
			time.Sleep(10 * time.Second)
			stopCapture(t, ate)

			checkEncapHeaders(t, dut, tc.nextHopGroupPaths, tc.wantAddEncapHeaders)

			var txPkts, rxPkts uint64
			// counters are not erased, so have to accumulate the packets from previous subtests.
			txPkts += gnmi.Get(t, otg, gnmi.OTG().Flow(flowName).Counters().OutPkts().State())
			rxPkts += gnmi.Get(t, otg, gnmi.OTG().Flow(flowName).Counters().InPkts().State())
			testCounters(t, dut, txPkts, rxPkts)

			validatePacketCapture(t, ate, tc.capturePort,
				&packetResult{
					mplsLabel:  tc.wantMPLSLabel,
					udpSrcPort: outerSrcUDPPort,
					udpDstPort: tc.wantOuterDstUDPPort,
					ipTTL:      tc.wantOuterIPTTL,
					srcIP:      tc.wantOuterSrcIP,
					dstIP:      tc.wantOuterDstIP,
				})

			slices.Reverse(tc.entries)

			c.DeleteEntries(t, tc.entries, tc.wantDelOperationResults)

			if loss := testTrafficv6(t, otg, atePort1, atePort2, tc.flowInnerDstIP, 5*time.Second); loss != 100 {
				t.Errorf("Loss: got %g, want 100", loss)
			}

			c.FlushAll(t)
			checkEncapHeaders(t, dut, tc.nextHopGroupPaths, tc.wantDelEncapHeaders)
		})
	}
}
