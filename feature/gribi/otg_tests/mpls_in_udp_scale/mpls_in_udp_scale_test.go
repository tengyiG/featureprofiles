package mpls_in_udp_scale_test

import (
	"testing"
	"time"

	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygot/ygot"
)

const (
	// Network configuration
	ethertypeIPv4   = oc.PacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV4
	ethertypeIPv6   = oc.PacketMatchTypes_ETHERTYPE_ETHERTYPE_IPV6
	clusterPolicy   = "vrf_selection_policy_c"
	ipv4PrefixLen   = 30
	ipv6PrefixLen   = 126
	trafficDuration = 15 * time.Second
	seqIDBase       = uint32(10)

	// Scale test configuration from TE-18.3 README
	// Physical topology: 8 ports (4 ingress, 4 egress)
	numPhysicalPorts     = 8
	numIngressPorts      = 4
	numEgressPorts       = 4
	numVLANsPerPort      = 8
	numLogicalInterfaces = 32 // 4 ingress ports * 8 VLANs each

	// Scale targets from README
	maxNHGs     = 20000
	maxNHs      = 20000
	maxPrefixes = 20000
	maxVRFs     = 1024

	// MPLS-in-UDP test configuration from README Test Parameters
	outerIPv6Src    = "2001:f:a:1::0"
	outerIPv6DstA   = "2001:f:c:e::1"
	outerIPv6DstB   = "2001:f:c:e::2"
	outerIPv6DstDef = "2001:1:1:1::0"
	outerDstUDPPort = uint16(5555)
	outerDSCP       = uint8(26)
	outerIPTTL      = uint8(64)

	// Inner IPv6 destinations from README
	innerIPv6DstA = "2001:aa:bb::1/128"
	innerIPv6DstB = "2001:aa:bb::2/128"

	// Inner IPv4 destinations from README
	ipv4InnerDstA = "10.5.1.1/32"
	ipv4InnerDstB = "10.5.1.2/32"

	// Traffic flow parameters from README
	ipv6FlowBase     = "2015:aa8::"
	ipv6PrefixBase   = "2015:aa8::/128"
	targetPacketLoss = 1.0 // ≤ 1%

	// gRIBI parameters from README
	nhIDStart  = uint64(201)
	nhgIDStart = uint64(10)

	// Static ARP configuration
	magicIP  = "192.168.1.1"
	magicMac = "02:00:00:00:00:01"

	// OTG capture limitation
	otgMultiPortCaptureSupported = false
)

var (
	otgDstPorts = []string{"port5", "port6", "port7", "port8"}
	otgSrcPorts = []string{"port1", "port2", "port3", "port4"}
)

// DUT port configurations following README Test Parameters
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

	otgPort2 = attrs.Attributes{
		Name:    "otgPort2",
		MAC:     "02:00:02:01:01:01",
		IPv4:    "192.0.2.6",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::6",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort3 = attrs.Attributes{
		Desc:    "dutPort3",
		MAC:     "02:01:00:00:00:03",
		IPv4:    "192.0.2.9",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::9",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort3 = attrs.Attributes{
		Name:    "otgPort3",
		MAC:     "02:00:03:01:01:01",
		IPv4:    "192.0.2.10",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::10",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort4 = attrs.Attributes{
		Desc:    "dutPort4",
		MAC:     "02:01:00:00:00:04",
		IPv4:    "192.0.2.13",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::13",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort4 = attrs.Attributes{
		Name:    "otgPort4",
		MAC:     "02:00:04:01:01:01",
		IPv4:    "192.0.2.14",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::14",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort5 = attrs.Attributes{
		Desc:    "dutPort5",
		MAC:     "02:01:00:00:00:05",
		IPv4:    "192.0.2.17",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::17",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort5 = attrs.Attributes{
		Name:    "otgPort5",
		MAC:     "02:00:05:01:01:01",
		IPv4:    "192.0.2.18",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::18",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort6 = attrs.Attributes{
		Desc:    "dutPort6",
		MAC:     "02:01:00:00:00:06",
		IPv4:    "192.0.2.21",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::21",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort6 = attrs.Attributes{
		Name:    "otgPort6",
		MAC:     "02:00:06:01:01:01",
		IPv4:    "192.0.2.22",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::22",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort7 = attrs.Attributes{
		Desc:    "dutPort7",
		MAC:     "02:01:00:00:00:07",
		IPv4:    "192.0.2.25",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::25",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort7 = attrs.Attributes{
		Name:    "otgPort7",
		MAC:     "02:00:07:01:01:01",
		IPv4:    "192.0.2.26",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::26",
		IPv6Len: ipv6PrefixLen,
	}

	dutPort8 = attrs.Attributes{
		Desc:    "dutPort8",
		MAC:     "02:01:00:00:00:08",
		IPv4:    "192.0.2.29",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::29",
		IPv6Len: ipv6PrefixLen,
	}

	otgPort8 = attrs.Attributes{
		Name:    "otgPort8",
		MAC:     "02:00:08:01:01:01",
		IPv4:    "192.0.2.30",
		IPv4Len: ipv4PrefixLen,
		IPv6:    "2001:f:d:e::30",
		IPv6Len: ipv6PrefixLen,
	}
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// configureDUT configures the DUT with 8 physical ports following te18.1 mpls_in_udp_test.go patterns
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	d := gnmi.OC()

	// Get all 8 physical ports
	ports := []*ondatra.Port{
		dut.Port(t, "port1"), dut.Port(t, "port2"), dut.Port(t, "port3"), dut.Port(t, "port4"),
		dut.Port(t, "port5"), dut.Port(t, "port6"), dut.Port(t, "port7"), dut.Port(t, "port8"),
	}

	// DUT port attributes following README Test Parameters
	dutPortAttrs := []attrs.Attributes{
		dutPort1, dutPort2, dutPort3, dutPort4,
		dutPort5, dutPort6, dutPort7, dutPort8,
	}

	// Configure physical interfaces
	for idx, port := range ports {
		attr := dutPortAttrs[idx]
		intf := attr.NewOCInterface(port.Name(), dut)

		// Configure 100G ports for specific vendors (from basic_encap_test.go)
		if port.PMD() == ondatra.PMD100GBASELR4 && dut.Vendor() != ondatra.CISCO && dut.Vendor() != ondatra.JUNIPER {
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

		gnmi.Replace(t, dut, d.Interface(port.Name()).Config(), intf)
	}

	// Configure base policies and network instances (from te18.1 mpls_in_udp_test.go)
	configureBaseConfig(t, dut)

	// Assign interfaces to network instances
	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		for _, port := range ports {
			fptest.AssignToNetworkInstance(t, dut, port.Name(), deviations.DefaultNetworkInstance(dut), 0)
		}
	}

	// Apply policy-based forwarding to ingress interfaces (ports 1-4)
	for i := 0; i < numIngressPorts; i++ {
		applyForwardingPolicy(t, dut, ports[i].Name())
	}

	// Set up static ARP configuration for gRIBI NH entries (from te18.1 patterns)
	if deviations.GRIBIMACOverrideWithStaticARP(dut) {
		staticARPWithSecondaryIP(t, dut)
	} else if deviations.GRIBIMACOverrideStaticARPStaticRoute(dut) {
		staticARPWithMagicUniversalIP(t, dut)
	}

	// Allow time for configuration to be applied
	time.Sleep(10 * time.Second)
}

// configureBaseConfig configures network instances and forwarding policy on the DUT
func configureBaseConfig(t *testing.T, dut *ondatra.DUTDevice) {
	fptest.ConfigureDefaultNetworkInstance(t, dut)
	pf := getPbrPolicy(dut, clusterPolicy)
	gnmi.Replace(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).PolicyForwarding().Config(), pf)
}

// getPbrRules returns policy-based routing rules for VRF selection
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
	}
	return []pbrRule{
		{
			sequence: 17,
			encapVrf: vrfDefault,
		},
	}
}

// seqIDOffset returns sequence ID with base offset to ensure proper ordering
func seqIDOffset(dut *ondatra.DUTDevice, i uint32) uint32 {
	if deviations.PfRequireSequentialOrderPbrRules(dut) {
		return i + seqIDBase
	}
	return i
}

// getPbrPolicy creates policy-based routing configuration for VRF selection
func getPbrPolicy(dut *ondatra.DUTDevice, name string) *oc.NetworkInstance_PolicyForwarding {
	d := &oc.Root{}
	ni := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	pf := ni.GetOrCreatePolicyForwarding()
	p := pf.GetOrCreatePolicy(name)
	p.SetType(oc.Policy_Type_VRF_SELECTION_POLICY)

	for _, pRule := range getPbrRules(dut) {
		r := p.GetOrCreateRule(seqIDOffset(dut, pRule.sequence))
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

// pbrRule defines a policy-based routing rule configuration
type pbrRule struct {
	sequence  uint32
	etherType oc.NetworkInstance_PolicyForwarding_Policy_Rule_L2_Ethertype_Union
	encapVrf  string
}

// applyForwardingPolicy applies the VRF selection policy to the ingress interface
func applyForwardingPolicy(t *testing.T, dut *ondatra.DUTDevice, ingressPort string) {
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

// staticARPWithSecondaryIP configures static ARP with secondary IP for gRIBI NH entries
func staticARPWithSecondaryIP(t *testing.T, dut *ondatra.DUTDevice) {
	// Get the first egress port for static ARP configuration
	port5 := dut.Port(t, "port5")

	// Configure secondary IP on the egress interface
	d := &oc.Root{}
	intf := d.GetOrCreateInterface(port5.Name()).GetOrCreateSubinterface(0)

	// Add secondary IPv6 address for static ARP
	secondaryIPv6 := "2001:f:d:e::100"
	ipv6Addr := intf.GetOrCreateIpv6().GetOrCreateAddress(secondaryIPv6)
	ipv6Addr.PrefixLength = ygot.Uint8(ipv6PrefixLen)
	gnmi.Replace(t, dut, gnmi.OC().Interface(port5.Name()).Subinterface(0).Ipv6().Address(secondaryIPv6).Config(), ipv6Addr)

	// Configure static neighbor entry
	neighbor := intf.GetOrCreateIpv6().GetOrCreateNeighbor(secondaryIPv6)
	neighbor.LinkLayerAddress = ygot.String(magicMac)
	gnmi.Replace(t, dut, gnmi.OC().Interface(port5.Name()).Subinterface(0).Ipv6().Neighbor(secondaryIPv6).Config(), neighbor)
}

// staticARPWithMagicUniversalIP configures static ARP with magic universal IP
func staticARPWithMagicUniversalIP(t *testing.T, dut *ondatra.DUTDevice) {
	// Get the first egress port for static ARP configuration
	port5 := dut.Port(t, "port5")

	// Configure static ARP entry with magic IP and MAC
	d := &oc.Root{}
	intf := d.GetOrCreateInterface(port5.Name()).GetOrCreateSubinterface(0)

	// Add static IPv4 neighbor entry
	neighbor := intf.GetOrCreateIpv4().GetOrCreateNeighbor(magicIP)
	neighbor.LinkLayerAddress = ygot.String(magicMac)
	gnmi.Replace(t, dut, gnmi.OC().Interface(port5.Name()).Subinterface(0).Ipv4().Neighbor(magicIP).Config(), neighbor)

	// Add corresponding static route if needed
	if deviations.GRIBIMACOverrideStaticARPStaticRoute(dut) {
		staticRoute := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).
			GetOrCreateStatic(magicIP + "/32")
		staticRoute.GetOrCreateNextHop("discard").NextHop = oc.LocalRouting_LOCAL_DEFINED_NEXT_HOP_DROP
		gnmi.Replace(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).
			Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).
			Static(magicIP+"/32").Config(), staticRoute)
	}
}

func TestMPLSOUDPEncapScale(t *testing.T) {
	// ctx := context.Background()

	// Configure DUT and ATE
	dut := ondatra.DUT(t, "dut")
	configureDUT(t, dut)
}
