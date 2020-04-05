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
	version string = "v0.0.1"
	qid     uint16
	destIP  net.IP
	err     error
)

var usage string = `
Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs.

Usage:
  fappfon-vpn-helper -q QUEUE -d DEST
  fappfon-vpn-helper -h | --help
  fappfon-vpn-helper --version

Options:
  -q QUEUE --queue=QUEUE  ID of netfilter_queue to attach.
  -d DEST --dest=DEST     Destination IPv4.
  -h --help               Show this help.
  -v --version            Show version.
`

func main() {
	err = parseArgs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Started fappfon-proxy.")

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

	fmt.Printf("Attaching to netfilter_queue with id '%d'\n", q.id)

	q.queue.Start() // blocking function
	defer q.queue.Stop()
}

func parseArgs() error {
	arguments, _ := docopt.ParseArgs(usage, nil, version)
	id, err := arguments.Int("--queue")
	if err != nil {
		return err
	}
	qid = uint16(id)
	ipStr, err := arguments.String("--dest")
	if err != nil {
		return err
	}
	destIP = net.ParseIP(ipStr)
	if destIP == nil {
		return errors.New("unable to parse destination IPv4")
	}

	return nil
}

// Handle a nfqueue packet. It implements nfqueue.PacketHandler interface.
func (q *Queue) Handle(p *nfqueue.Packet) {
	fmt.Println("Analyzing new packet..")
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
		fmt.Println("Sent modified packet.")
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
			fmt.Printf("Packet is from Fritz!Box, skipping.\n\n")
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
		fmt.Println("SIP packet detected.")
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
		fmt.Println("Error decoding some part of the packet:", err)
	}

	return packet
}
