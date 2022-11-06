package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/pborman/ansi"
)

var count = 0

var (
	device  string        = "en1"
	snaplen int32         = 65535
	promisc bool          = false
	timeout time.Duration = -1
	handle  *pcap.Handle
)

var (
	ESCAPE = ansi.ESC + "[0;m"

	ITAL      = "\033[3m"
	BLD_UNDER = "\033[1;4m"

	BLD_YELLOW = ansi.BoldYellowText

	SRC_TARGET_OUTLINE = "\033[2;3;31m" // red italic
	DST_SOURCE_OUTLINE = "\033[2;3m"    // grey italic
)

func handleInterrupt(c chan os.Signal) {
	start := time.Now()
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c

		fmt.Printf("\n%d TCP packets with SYN flags set captured\n%v elapsed since start\n", count, time.Since(start))
		os.Exit(1)
	}()
}

var setHost bool

func detectTCPSYNPacket(packet gopacket.Packet, host string) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)

	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		var srcIP, dstIP = ip.SrcIP, ip.DstIP

		// If Network layer get TCP data
		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			var srcPort, dstPort = tcp.SrcPort, tcp.DstPort

			if len(ip.DstIP.String()) > 0 {
				count++

				var (
					SRC_IP = fmt.Sprintf("%v%s%v", SRC_TARGET_OUTLINE, srcIP, ESCAPE)
					DST_IP = fmt.Sprintf("%v%s%v", DST_SOURCE_OUTLINE, dstIP, ESCAPE)
				)

				if setHost == true && ip.SrcIP.String() == host {

					// THA - Target Host Acquisition // IP address was set
					fmt.Printf("** %vPACKET \033[0;32m(THA)\033[0;m%v - %vSRC%v=\033[0;32m%v\033[0;m(%v) => %vDST%v=%v(%v) at %s **\n", BLD_YELLOW, ESCAPE,
						BLD_UNDER, ESCAPE, ip.SrcIP.String(), srcPort, BLD_UNDER, ESCAPE, DST_IP, dstPort, time.Now())

				} else {
					// NHS - Null Host Source // IP address not set
					fmt.Printf("** %vPACKET (NHS)%v - %vSRC%v=%v(%v) => %vDST%v=%v(%v) at %s **\n", BLD_YELLOW, ESCAPE,
						BLD_UNDER, ESCAPE, SRC_IP, srcPort, BLD_UNDER, ESCAPE, DST_IP, dstPort, time.Now())
				}

				// fmt.Printf("** %vSYN PACKET%v - %vSRC%v=%v(%v) => %vDST%v=%v(%v) at %s **\n", BLD_YELLOW, ESCAPE,
				// 	BLD_UNDER, ESCAPE, SRC_IP, srcPort, BLD_UNDER, ESCAPE, DST_IP, dstPort, time.Now())
			}
		}
	}
}

func main() {
	if pcap.Version() == "" {
		fmt.Fprintf(os.Stderr, "FATAL: Libpcap is not installed. Install it for your host OS and try again!")
		os.Exit(1)
	}

	file := fmt.Sprintf("ext/pcap_out/%s_ouput.pcap", time.Now())

	f, _ := os.Create(file)
	w := pcapgo.NewWriter(f)

	w.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet)

	c := make(chan os.Signal)
	handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exception: %v\n", err)
		os.Exit(1)
	}

	defer handle.Close()

	err = handle.SetBPFFilter("tcp")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exception: %v\n", err)
		os.Exit(0)
	}

	fmt.Printf("[SETFILTER] Set BPF TCP filter at %v\n", time.Now())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	handleInterrupt(c)

	fmt.Println("++ Starting TCP packet capture for SYN flags ++\n")

	switch len(os.Args) {
	case 1:
		fmt.Println("-- Not setting remote host\n")
		setHost = false

		for packet := range packetSource.Packets() {
			detectTCPSYNPacket(packet, "")
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

	case 2:
		target := string(os.Args[1])
		fmt.Printf("++ Target set to: \033[0;32m%v\033[0;m ++\n", target)

		setHost = true

		for packet := range packetSource.Packets() {
			detectTCPSYNPacket(packet, target)
			w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}
	}
}
