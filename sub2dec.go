package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

// build v0.1

var index int
var maxSubnetLength = 32

func retIndex(s string) string {
	n := len(s)

	if n <= 3 {
		return s
	}

	return retIndex(s[:n-3]) + "," + s[n-3:]
}

func main() {
	subnetMaskFlag := flag.String("csm", string(os.Args[1]), "classful subnet mask")
	flag.Parse()

	var (
		banner       = "sub2dec v0.1 (classful subnet mask)"
		bannerFooter = strings.Repeat("=", len(banner))
		subnetMask   = *subnetMaskFlag
	)

	var getMaskLen int

	subnetMaskID := strings.Split(subnetMask, "/")[1] // os.Args[1] - "/"
	intSubnetMaskID, _ := strconv.Atoi(subnetMaskID)

	if intSubnetMaskID > maxSubnetLength {
		subnetMaskID = "24"
		subnetMask = "/24"
		getMaskLen = 24

	} else {
		getMaskRepeat := strings.Repeat("1", intSubnetMaskID)
		getMaskLen = len(getMaskRepeat)
	}

	fmt.Printf("%s\n%s\nSubnet Mask: %s\n", string(banner), bannerFooter, subnetMask+"\n")
	fmt.Printf("Decimal Format: %s >> (%d bits)\n", subnetMask, getMaskLen)

	var (
		subnetMaskInt, _ = strconv.Atoi(subnetMaskID)
		oneRepeat        = strings.Repeat("1", subnetMaskInt)

		oneGetLen    = len(oneRepeat)
		oneStrGetLen = strconv.Itoa(oneGetLen)
		oneLen, _    = strconv.Atoi(oneStrGetLen)

		zeroRepeat = strings.Repeat("0", maxSubnetLength-oneLen)
	)

	fmt.Printf("NetworkID=%s (len:%d)\n", oneRepeat, len(oneRepeat))
	fmt.Printf("HostID=%s (len:%d)\n\n", zeroRepeat, len(zeroRepeat))

	hosts64 := float64(len(zeroRepeat))
	var possibleHosts float64

	if hosts64 <= 0 {
		possibleHosts = 0

	} else {
		possibleHosts = math.Pow(2, hosts64) - 2
	}

	intTotalHosts := int(possibleHosts)
	strTotalHosts := strconv.Itoa(intTotalHosts)

	fmt.Printf("Possible Hosts: %s\nFSM = %s (bin fmt)\n\n", retIndex(strTotalHosts), oneRepeat+"|"+zeroRepeat)

	var (
		decLength = len(oneRepeat) + len(zeroRepeat) // bit length of the subnet mask

		strDecLength    = strconv.Itoa(decLength)
		intDecLength, _ = strconv.Atoi(strDecLength)

		decFinal      = strconv.Itoa(decLength)
		numberOfEight = intDecLength / 8
	)

	fmt.Printf("Total = %s bits (%d bytes)\n", decFinal, numberOfEight)
}
