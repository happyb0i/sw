package sw

import (
	"fmt"
	"github.com/alouca/gosnmp"
	"log"
	"strconv"
	"strings"
	"time"
)

type IfStats struct {
	IfName           string
	IfIndex          int
	IfHCInOctets     int64
	IfHCOutOctets    int64
	IfHCInUcastPkts  int64
	IfHCOutUcastPkts int64
	TS               int64
}

func (this *IfStats) String() string {
	return fmt.Sprintf("<IfName:%s, IfIndex:%d, IfHCInOctets:%d, IfHCOutOctets:%d>", this.IfName, this.IfIndex, this.IfHCInOctets, this.IfHCOutOctets)
}

func ListIfStats(ip, community string, timeout int, ignoreIface []string, retry int, ignorePkt bool) ([]IfStats, error) {
	var ifStatsList []IfStats

	chIfInList := make(chan []gosnmp.SnmpPDU)
	chIfOutList := make(chan []gosnmp.SnmpPDU)

	chIfNameList := make(chan []gosnmp.SnmpPDU)

	go ListIfHCInOctets(ip, community, timeout, chIfInList, retry)
	go ListIfHCOutOctets(ip, community, timeout, chIfOutList, retry)

	go ListIfName(ip, community, timeout, chIfNameList, retry)

	ifInList := <-chIfInList
	ifOutList := <-chIfOutList

	ifNameList := <-chIfNameList

	chIfInPktList := make(chan []gosnmp.SnmpPDU)
	chIfOutPktList := make(chan []gosnmp.SnmpPDU)

	var ifInPktList, ifOutPktList []gosnmp.SnmpPDU

	if ignorePkt == false {
		go ListIfHCInUcastPkts(ip, community, timeout, chIfInPktList, retry)
		go ListIfHCOutUcastPkts(ip, community, timeout, chIfOutPktList, retry)
		ifInPktList = <-chIfInPktList
		ifOutPktList = <-chIfOutPktList
	}

	if len(ifNameList) > 0 && len(ifInList) > 0 && len(ifOutList) > 0 {

		now := time.Now().Unix()

		for _, ifNamePDU := range ifNameList {

			ifName := ifNamePDU.Value.(string)

			check := true
			if len(ignoreIface) > 0 {
				for _, ignore := range ignoreIface {
					if strings.Contains(ifName, ignore) {
						check = false
						break
					}
				}
			}

			defer func() {
				if r := recover(); r != nil {
					log.Println("Recovered in ListIfStats", r)
				}
			}()

			if check {
				var ifStats IfStats

				ifIndexStr := strings.Replace(ifNamePDU.Name, ".1.3.6.1.2.1.31.1.1.1.1.", "", 1)

				ifStats.IfIndex, _ = strconv.Atoi(ifIndexStr)

				for ti, ifHCInOctetsPDU := range ifInList {
					if strings.Replace(ifHCInOctetsPDU.Name, ".1.3.6.1.2.1.31.1.1.1.6.", "", 1) == ifIndexStr {

						ifStats.IfHCInOctets = ifInList[ti].Value.(int64)
						ifStats.IfHCOutOctets = ifOutList[ti].Value.(int64)

						if ignorePkt == false {
							ifStats.IfHCInUcastPkts = ifInPktList[ti].Value.(int64)
							ifStats.IfHCOutUcastPkts = ifOutPktList[ti].Value.(int64)
						}

						ifStats.TS = now
						ifStats.IfName = ifName
					}
				}

				ifStatsList = append(ifStatsList, ifStats)

			}
		}
	}

	return ifStatsList, nil
}

func ListIfHCInOctets(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int) {
	oid := "1.3.6.1.2.1.31.1.1.1.6"
	RunSnmpRetry(ip, community, timeout, ch, retry, oid)
}

func ListIfHCOutOctets(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int) {
	oid := "1.3.6.1.2.1.31.1.1.1.10"
	RunSnmpRetry(ip, community, timeout, ch, retry, oid)
}

func ListIfHCInUcastPkts(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int) {
	oid := "1.3.6.1.2.1.31.1.1.1.7"
	RunSnmpRetry(ip, community, timeout, ch, retry, oid)
}

func ListIfHCOutUcastPkts(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int) {
	oid := "1.3.6.1.2.1.31.1.1.1.11"
	RunSnmpRetry(ip, community, timeout, ch, retry, oid)
}

func ListIfName(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int) {
	oid := "1.3.6.1.2.1.31.1.1.1.1"
	RunSnmpRetry(ip, community, timeout, ch, retry, oid)
}

func RunSnmpRetry(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, oid string) {
	method := "walk"
	var snmpPDUs []gosnmp.SnmpPDU

	for i := 0; i < retry; i++ {
		snmpPDUs, _ = RunSnmp(ip, community, oid, method, timeout)
		if len(snmpPDUs) > 0 {
			ch <- snmpPDUs
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	ch <- snmpPDUs
	return
}
