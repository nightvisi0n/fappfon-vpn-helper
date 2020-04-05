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
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"sync"
	"syscall"

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
	mux           sync.Mutex
)

var usage string = `
Daemon that forces FRITZ!App Fon to work over non FRITZ!Box VPNs.

Usage:
  fappfon-vpn-helper [-v|-vv] -q QUEUE -f FBOX
  fappfon-vpn-helper -h | --help
  fappfon-vpn-helper --version

Options:
  -q QUEUE --queue=QUEUE  ID of netfilter_queue to attach.
  -f FBOX --fbox=FBOX     DNS name or IPv4 of FRITZ!Box.
  -v                      Increase verbosity of logging to INFO
  -vv                     Increase verbosity of logging to DEBUG
  -h --help               Show this help.
  --version               Show version.
`

func main() {
	var q *Queue

	logrus.SetLevel(logrus.InfoLevel)
	logrus.RegisterExitHandler(func() {
		if q != nil {
			mux.Lock()
			_ = q.queue.Stop()
			logrus.Infof("Stopping netfilter_queue with id '%d'\n", q.id)
		}
	})

	sigs := make(chan os.Signal)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		logrus.Infoln("Got SIGINT, shutting down gracefully")
		logrus.Exit(0)
	}()

	packetCounter = big.NewInt(0)

	err = parseArgs()
	if err != nil {
		logrus.Fatal(err)
	}

	logrus.Infoln("Started fappfon-vpn-helper")

	q = &Queue{
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
		q = nil
		if err.Error() == "Error in nfqueue_create_queue" {
			logrus.Errorf("%v: This is most likely a permission problem", err)
			logrus.Fatalf("Try to run this program as 'root' or run docker container with '--cap-add=NET_ADMIN'")
		} else {
			logrus.Fatal(err)
		}
	}
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

	fboxStr, err := arguments.String("--fbox")
	if err != nil {
		return err
	}
	fboxAddr, err := net.LookupHost(fboxStr)
	if err != nil {
		return err
	}
	destIP = net.ParseIP(fboxAddr[0])
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
	mux.Lock()

	defer func() {
		packetCounter = packetCounter.Add(packetCounter, big.NewInt(1))
		mux.Unlock()
	}()

	logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).Debugln("Analyzing new packet..")

	packet := gopacket.NewPacket(p.Buffer, layers.LayerTypeIPv4, gopacket.Default)
	newPacket, err := parseSipPacket(packet)

	switch err {
	case nil:
	case errFRITZPacket:
		logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
			Debugln(err)
		p.Accept()
		logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
			Debugln("Sent unmodified packet")
		return
	default:
		logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
			Errorln("Error decoding some part of the packet: ", packetCounter)
		p.Accept()
		logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
			Errorln("Sent unmodified packet")
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
			logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
				Errorln("Error building a modified packet: ", err)
			p.Accept()
			logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
				Errorln("Sent unmodified packet")
			return
		}

		p.Modify(buffer.Bytes())
		logrus.WithFields(logrus.Fields{"packetNum": packetCounter}).
			Debugln("Sent modified packet")
	} else {
		p.Accept()
	}
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
