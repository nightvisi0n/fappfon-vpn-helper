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
	"math/big"
	"net"
	"regexp"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/Telefonica/nfqueue"

	"github.com/docopt/docopt-go"

	"github.com/sirupsen/logrus"
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

	errIPv4Decoding error = errors.New("Unable to decode IPv4 layer")
	errUDPDecoding  error = errors.New("Unable to decode UDP layer")
	errSIPDecoding  error = errors.New("Unable to decode SIP layer")
	errFRITZPacket  error = errors.New("Packet originates from FRITZ!Box")

	qid    uint16
	destIP net.IP

	err error

	packetCounter *big.Int
)

var usage string = `
Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs.

Usage:
  fappfon-vpn-helper [-v|-vv] -q QUEUE -f FIP
  fappfon-vpn-helper -h | --help
  fappfon-vpn-helper --version

Options:
  -q QUEUE --queue=QUEUE  ID of netfilter_queue to attach.
  -f FIP --fip=FIP        IPv4 of FRITZ!Box.
  -v                      Increase verbosity of logging to INFO
  -vv                     Increase verbosity of logging to DEBUG
  -h --help               Show this help.
  --version               Show version.
`

func main() {
	logrus.SetLevel(logrus.InfoLevel)

	packetCounter = big.NewInt(0)

	err = parseArgs()
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infoln("Started fappfon-vpn-helper")

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

	logrus.Infof("Ready to process packets from netfilter_queue with id '%d'\n", q.id)

	err = q.queue.Start() // blocking function
	if err != nil {
		if err.Error() == "Error in nfqueue_create_queue" {
			logrus.Errorf("%v: This is most likely a permission problem", err)
			logrus.Fatalf("Try to run this program as 'root' or run docker container with '--cap-add=NET_ADMIN'")
		} else {
			logrus.Fatal(err)
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

	logLevel := arguments["-v"].(int)
	switch logLevel {
	case 1:
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debugln("Set log level to DEBUG")
	case 2:
		logrus.SetLevel(logrus.TraceLevel)
		logrus.Traceln("Set log level to TRACE")
	}

	return nil
}

// Handle a nfqueue packet. It implements nfqueue.PacketHandler interface.
func (q *Queue) Handle(p *nfqueue.Packet) {
	defer increasePacketCounter()

	logrus.Debugf("[%s] Analyzing new packet..\n", packetCounter)

	packet := gopacket.NewPacket(p.Buffer, layers.LayerTypeIPv4, gopacket.Default)
	newPacket, err := parseSipPacket(packet)

	switch err {
	case nil:
	case errFRITZPacket:
		logrus.Debugf("[%s] %s\n", packetCounter, err)
		p.Accept()
		logrus.Debugf("[%s] Sent unmodified packet\n", packetCounter)
		return
	default:
		logrus.Errorf("[%s] Error decoding some part of the packet: %s\n", packetCounter, err)
		p.Accept()
		logrus.Errorf("[%s] Sent unmodified packet\n", packetCounter)
		return
	}

	if newPacket != nil {
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		err = gopacket.SerializePacket(buffer, options, newPacket)
		if err != nil {
			logrus.Errorf("[%s] Error building a modified packet: %s\n", packetCounter, err)
			p.Accept()
			logrus.Errorf("[%s] Sent unmodified packet.\n", packetCounter)
			return
		}

		p.Modify(buffer.Bytes())
		logrus.Debugf("[%s] Sent modified packet.\n", packetCounter)
	} else {
		p.Accept()
	}
}

func increasePacketCounter() {
	packetCounter = packetCounter.Add(packetCounter, big.NewInt(1))
}

func parseSipPacket(packet gopacket.Packet) (gopacket.Packet, error) {
	var srcIP net.IP

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		srcIP = ip.SrcIP

		if net.IP.Equal(ip.SrcIP, destIP) {
			return nil, errFRITZPacket
		}
	} else {
		return nil, errIPv4Decoding
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)

		udp.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
	} else {
		return nil, errUDPDecoding
	}

	sipLayer := packet.Layer(layers.LayerTypeSIP)
	if sipLayer != nil {
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
		return nil, errSIPDecoding
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		return nil, err.Error()
	}

	return packet, nil
}
