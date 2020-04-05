// fappfon-vpn-helper - Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs
// Copyright (C) 2020  nightvisi0n <dev@jneureuther.de>

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// FRITZ!Box and FRITZ!App Fon are trademarks of AVM Computersysteme Vertriebs GmbH, Berlin, Germany.
package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/Telefonica/nfqueue"

	"github.com/docopt/docopt-go"
)

// Queue struct
type Queue struct {
	id    uint16
	queue *nfqueue.Queue
}

var (
	// GitSummary is the output of `git describe --tags --dirty --always`
	GitSummary string = "undefined"
	// BuildDate is the RFC3339 formatted UTC build date
	BuildDate string = "undefined"

	qid    uint16
	destIP net.IP
	err    error
	lErr   *log.Logger
	lOut   *log.Logger
)

var usage string = `
Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs.

Usage:
  fappfon-vpn-helper -q QUEUE -f FIP
  fappfon-vpn-helper -h | --help
  fappfon-vpn-helper -v | --version

Options:
  -q QUEUE --queue=QUEUE  ID of netfilter_queue to attach.
  -f FIP --fip=FIP        IPv4 of FRITZ!Box.
  -h --help               Show this help.
  -v --version            Show version.
`

func main() {
	lErr = log.New(os.Stderr, "\t[ERR] ", log.LstdFlags|log.Lmsgprefix)
	lOut = log.New(os.Stdout, "\t", log.LstdFlags|log.Lmsgprefix)

	err = parseArgs()
	if err != nil {
		lErr.Fatal(err)
	}

	lOut.Println("Started fappfon-proxy.")

	q := &Queue{
		id: qid,
	}
	queueCfg := &nfqueue.QueueConfig{
		MaxPackets: 1000,
		BufferSize: 16 * 1024 * 1024,
		QueueFlags: []nfqueue.QueueFlag{nfqueue.FailOpen},
	}
	// Pass as packet handler the current instance because it implements nfqueue.PacketHandler interface
	q.queue = nfqueue.NewQueue(q.id, q, queueCfg)

	lOut.Printf("Attaching to netfilter_queue with id '%d'\n", q.id)

	err = q.queue.Start() // blocking function
	if err != nil {
		if err.Error() == "Error in nfqueue_create_queue" {
			lErr.Fatalf("%v: This is most likely a permission problem. Try to run this program as 'root' or run docker container with '--cap-add=NET_ADMIN'.", err)
		} else {
			lErr.Fatal(err)
		}
	}
	defer q.queue.Stop()
}

func parseArgs() error {
	versionStr := fmt.Sprintf("Version %s, built at %s", GitSummary, BuildDate)
	arguments, err := docopt.ParseArgs(usage, nil, versionStr)
	if err != nil {
		return err
	}

	qIDInt, err := arguments.Int("--queue")
	if err != nil {
		return err
	}
	qid = uint16(qIDInt)
	ipStr, err := arguments.String("--fip")
	if err != nil {
		return err
	}
	destIP = net.ParseIP(ipStr)
	if destIP == nil {
		return errors.New("Unable to parse destination IPv4")
	}

	return nil
}

// Handle a nfqueue packet. It implements nfqueue.PacketHandler interface.
func (q *Queue) Handle(p *nfqueue.Packet) {
	lOut.Println("Analyzing new packet..")
	packet := gopacket.NewPacket(p.Buffer, layers.LayerTypeIPv4, gopacket.Default)
	newPacket := parseSipPacket(packet)
	if newPacket != nil {
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		err = gopacket.SerializePacket(buffer, options, newPacket)
		if err != nil {
			log.Fatal(err)
		}

		p.Modify(buffer.Bytes())
		lOut.Println("Sent modified packet.")
	} else {
		p.Accept()
	}
}

func parseSipPacket(packet gopacket.Packet) gopacket.Packet {
	var srcIP net.IP

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		srcIP = ip.SrcIP

		if net.IP.Equal(ip.SrcIP, destIP) {
			lOut.Printf("Packet is from Fritz!Box, skipping.\n\n")
			return nil
		}
	} else {
		return nil
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)

		udp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
	} else {
		return nil
	}

	sipLayer := packet.Layer(layers.LayerTypeSIP)
	if sipLayer != nil {
		lOut.Println("SIP packet detected.")
		sip, _ := sipLayer.(*layers.SIP)

		ipv4Regexp := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`)

		for i, v := range sip.Headers["via"] {
			sip.Headers["via"][i] = ipv4Regexp.ReplaceAllString(v, srcIP.String())
		}

		for i, c := range sip.Headers["contact"] {
			sip.Headers["contact"][i] = ipv4Regexp.ReplaceAllString(c, srcIP.String())
		}

		if len(sip.Payload()) > 0 {
			sip.BaseLayer.Payload = ipv4Regexp.ReplaceAll(sip.BaseLayer.Payload, []byte(srcIP.String()))
			sip.Headers["content-length"][0] = strconv.Itoa(len(sip.Payload()))
		}
	} else {
		return nil
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		lErr.Println("Error decoding some part of the packet:", err)
	}

	return packet
}