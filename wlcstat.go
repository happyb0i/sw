package sw

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gaochao1/gosnmp"
)

const (
	//AP
	apNameOid                         = "1.3.6.1.4.1.9.9.513.1.1.1.1.5"
	apNameOidPrefix                   = ".1.3.6.1.4.1.9.9.513.1.1.1.1.5."
	apUpTimeOid                       = "1.3.6.1.4.1.9.9.513.1.1.1.1.6"
	apUpTimeOidPrefix                 = ".1.3.6.1.4.1.9.9.513.1.1.1.1.6."
	apPowerStatusOid                  = "1.3.6.1.4.1.9.9.513.1.1.1.1.20"
	apPowerStatusOidPrefix            = ".1.3.6.1.4.1.9.9.513.1.1.1.1.20."
	apAssociatedClientCountOid        = "1.3.6.1.4.1.9.9.513.1.1.1.1.54"
	apAssociatedClientCountOidPrefix  = ".1.3.6.1.4.1.9.9.513.1.1.1.1.54."
	apMemoryCurrentUsageOid           = "1.3.6.1.4.1.9.9.513.1.1.1.1.55"
	apMemoryCurrentUsageOidPrefix     = ".1.3.6.1.4.1.9.9.513.1.1.1.1.55."
	apCpuCurrentUsageOid              = "1.3.6.1.4.1.9.9.513.1.1.1.1.57"
	apCpuCurrentUsageOidPrefix        = ".1.3.6.1.4.1.9.9.513.1.1.1.1.57."
	apConnectCountOid                 = "1.3.6.1.4.1.9.9.513.1.1.1.1.66"
	apConnectCountOidPrefix           = ".1.3.6.1.4.1.9.9.513.1.1.1.1.66."
	apReassocFailCountOid             = "1.3.6.1.4.1.9.9.513.1.1.1.1.68"
	apReassocFailCountOidPrefix       = ".1.3.6.1.4.1.9.9.513.1.1.1.1.68."
	apAssocFailTimesOid               = "1.3.6.1.4.1.9.9.513.1.1.1.1.75"
	apAssocFailTimesOidPrefix         = ".1.3.6.1.4.1.9.9.513.1.1.1.1.75."
	apEthernetIfInputErrorsOid        = "1.3.6.1.4.1.9.9.513.1.2.2.1.17"
	apEthernetIfInputErrorsOidPrefix  = ".1.3.6.1.4.1.9.9.513.1.2.2.1.17."
	apEthernetIfOutputErrorsOid       = "1.3.6.1.4.1.9.9.513.1.2.2.1.31"
	apEthernetIfOutputErrorsOidPrefix = ".1.3.6.1.4.1.9.9.513.1.2.2.1.31."
	apHaPrimaryUnitOid                = "10.12.99.2 1.3.6.1.4.1.9.9.198888.0.1.12"
	apHaPrimaryUnitOidPrefix          = "10.12.99.2 1.3.6.1.4.1.9.9.198888.0.1.12."
)

type WlcStats struct {
	TS                       int64
	ApIndex                  string
	ApName                   string
	ApUpTime                 int
	ApPowerStatus            int
	ApAssociatedClientCount  int
	ApEthernetIfInputErrors  int
	ApEthernetIfOutputErrors int
	ApMemoryCurrentUsage     int
	ApCpuCurrentUsage        int
	ApConnectCount           int
	ApReassocFailCount       int
	ApAssocFailTimes         int
	ApHaPrimaryUnit          int
}

//type WlcStats struct {
//	TS                   int64
//	ApIndex	string
//        ApName	string
//	ApPowerStatus	uint64
//	ApAssociatedClientCount	uint64
//	ApMemoryCurrentUsage	uint64
//	ApCpuCurrentUsage	uint64
//	ApConnectCount	uint64
//	ApReassocFailCount	uint64
//	ApAssocFailTimes	uint64
//	ApEthernetIfInputErrors	uint64
//}

func (this *WlcStats) String() string {
	//return fmt.Sprintf("<IfName:%s, IfIndex:%d, IfHCInOctets:%d, IfHCOutOctets:%d>", this.IfName, this.IfIndex, this.IfHCInOctets, this.IfHCOutOctets)
	return fmt.Sprintf("<ApName:%s, ApIndex:%s>", this.ApName, this.ApIndex)
}

func ListWlcStats(ip, community string, timeout int, ignoreIface []string, retry int, limitConn int, ignorePkt bool, ignoreOperStatus bool, ignoreBroadcastPkt bool, ignoreMulticastPkt bool, ignoreDiscards bool, ignoreErrors bool, ignoreUnknownProtos bool, ignoreOutQLen bool) ([]WlcStats, error) {
	var wlcStatsList []WlcStats
	var limitCh chan bool
	if limitConn > 0 {
		limitCh = make(chan bool, limitConn)
	} else {
		limitCh = make(chan bool, 1)
	}

	defer func() {
		if r := recover(); r != nil {
			log.Println(ip+" Recovered in ListWlcStats", r)
		}
	}()
	chApNameList := make(chan []gosnmp.SnmpPDU)
	chApUpTimeList := make(chan []gosnmp.SnmpPDU)
	chApPowerStatusList := make(chan []gosnmp.SnmpPDU)
	chApAssociatedClientCountList := make(chan []gosnmp.SnmpPDU)
	chApEthernetIfInputErrorsList := make(chan []gosnmp.SnmpPDU)
	chApEthernetIfOutputErrorsList := make(chan []gosnmp.SnmpPDU)
	chApMemoryCurrentUsageList := make(chan []gosnmp.SnmpPDU)
	chApCpuCurrentUsageList := make(chan []gosnmp.SnmpPDU)
	chApConnectCountList := make(chan []gosnmp.SnmpPDU)
	chApReassocFailCountList := make(chan []gosnmp.SnmpPDU)
	chApAssocFailTimesList := make(chan []gosnmp.SnmpPDU)
	chapHaPrimaryUnitList := make(chan []gosnmp.SnmpPDU)

	limitCh <- true
	go ListApName(ip, community, timeout, chApNameList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApUpTime(ip, community, timeout, chApUpTimeList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApPowerStatus(ip, community, timeout, chApPowerStatusList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApAssociatedClientCount(ip, community, timeout, chApAssociatedClientCountList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApEthernetIfInputErrors(ip, community, timeout, chApEthernetIfInputErrorsList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApEthernetIfOutputErrors(ip, community, timeout, chApEthernetIfOutputErrorsList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApMemoryCurrentUsage(ip, community, timeout, chApMemoryCurrentUsageList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApCpuCurrentUsage(ip, community, timeout, chApCpuCurrentUsageList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApConnectCount(ip, community, timeout, chApConnectCountList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApReassocFailCount(ip, community, timeout, chApReassocFailCountList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListApAssocFailTimes(ip, community, timeout, chApAssocFailTimesList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)
	limitCh <- true
	go ListHaPrimaryUnit(ip, community, timeout, chapHaPrimaryUnitList, retry, limitCh)
	time.Sleep(5 * time.Millisecond)

	apNameList := <-chApNameList
	apUpTimeList := <-chApUpTimeList
	apPowerStatusList := <-chApPowerStatusList
	apAssociatedClientCountList := <-chApAssociatedClientCountList
	apEthernetIfInputErrorsList := <-chApEthernetIfInputErrorsList
	apEthernetIfOutputErrorsList := <-chApEthernetIfOutputErrorsList
	apMemoryCurrentUsageList := <-chApMemoryCurrentUsageList
	apCpuCurrentUsageList := <-chApCpuCurrentUsageList
	apConnectCountList := <-chApConnectCountList
	apReassocFailCountList := <-chApReassocFailCountList
	apAssocFailTimesList := <-chApAssocFailTimesList
	apHaPrimaryUnitList := <-chapHaPrimaryUnitList

	if len(apNameList) > 0 && len(apPowerStatusList) > 0 {
		now := time.Now().Unix()

		for _, apNamePDU := range apNameList {

			apName := apNamePDU.Value.(string)

			check := true
			if check {
				var wlcStats WlcStats
				apIndexStr := strings.Replace(apNamePDU.Name, apNameOidPrefix, "", 1)

				wlcStats.ApIndex = apIndexStr

				for ti, apPowerStatusPDU := range apPowerStatusList {
					if strings.Replace(apPowerStatusPDU.Name, apPowerStatusOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApPowerStatus = apPowerStatusList[ti].Value.(int)
						break
					}
				}

				for ti, apUpTimePDU := range apUpTimeList {
					if strings.Replace(apUpTimePDU.Name, apUpTimeOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApUpTime = apUpTimeList[ti].Value.(int)
						break
					}
				}

				for ti, apAssociatedClientCountPDU := range apAssociatedClientCountList {
					if strings.Replace(apAssociatedClientCountPDU.Name, apAssociatedClientCountOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApAssociatedClientCount = apAssociatedClientCountList[ti].Value.(int)
						break
					}
				}

				for ti, apEthernetIfInputErrorsPDU := range apEthernetIfInputErrorsList {
					if strings.Replace(apEthernetIfInputErrorsPDU.Name, apEthernetIfInputErrorsOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApEthernetIfInputErrors = apEthernetIfInputErrorsList[ti].Value.(int)
						break
					}
				}

				for ti, apEthernetIfOutputErrorsPDU := range apEthernetIfOutputErrorsList {
					if strings.Replace(apEthernetIfOutputErrorsPDU.Name, apEthernetIfOutputErrorsOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApEthernetIfOutputErrors = apEthernetIfOutputErrorsList[ti].Value.(int)
						break
					}
				}

				for ti, apMemoryCurrentUsagePDU := range apMemoryCurrentUsageList {
					if strings.Replace(apMemoryCurrentUsagePDU.Name, apMemoryCurrentUsageOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApMemoryCurrentUsage = apMemoryCurrentUsageList[ti].Value.(int)
						break
					}
				}

				for ti, apCpuCurrentUsagePDU := range apCpuCurrentUsageList {
					if strings.Replace(apCpuCurrentUsagePDU.Name, apCpuCurrentUsageOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApCpuCurrentUsage = apCpuCurrentUsageList[ti].Value.(int)
						break
					}
				}

				for ti, apConnectCountPDU := range apConnectCountList {
					if strings.Replace(apConnectCountPDU.Name, apConnectCountOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApConnectCount = apConnectCountList[ti].Value.(int)
						break
					}
				}

				for ti, apReassocFailCountPDU := range apReassocFailCountList {
					if strings.Replace(apReassocFailCountPDU.Name, apReassocFailCountOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApReassocFailCount = apReassocFailCountList[ti].Value.(int)
						break
					}
				}

				for ti, apAssocFailTimesPDU := range apAssocFailTimesList {
					if strings.Replace(apAssocFailTimesPDU.Name, apAssocFailTimesOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApAssocFailTimes = apAssocFailTimesList[ti].Value.(int)
						break
					}
				}

				for ti, apHaPrimaryUnitPDU := range apHaPrimaryUnitList {
					if strings.Replace(apHaPrimaryUnitPDU.Name, apHaPrimaryUnitOidPrefix, "", 1) == apIndexStr {
						wlcStats.ApHaPrimaryUnit = apHaPrimaryUnitList[ti].Value.(int)
						break
					}
				}

				wlcStats.TS = now
				wlcStats.ApName = apName
				wlcStatsList = append(wlcStatsList, wlcStats)
			}
		}
	}
	return wlcStatsList, nil
}

func ListApName(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apNameOid)
}

func ListApPowerStatus(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apPowerStatusOid)
}

func ListApUpTime(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apUpTimeOid)
}

func ListApAssociatedClientCount(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apAssociatedClientCountOid)
}

func ListApEthernetIfInputErrors(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apEthernetIfInputErrorsOid)
}

func ListApEthernetIfOutputErrors(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apEthernetIfOutputErrorsOid)
}

func ListApMemoryCurrentUsage(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apMemoryCurrentUsageOid)
}

func ListApCpuCurrentUsage(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apCpuCurrentUsageOid)
}

func ListApConnectCount(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apConnectCountOid)
}

func ListApReassocFailCount(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apReassocFailCountOid)
}

func ListApAssocFailTimes(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apAssocFailTimesOid)
}

func ListHaPrimaryUnit(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool) {
	RunSnmpRetry(ip, community, timeout, ch, retry, limitCh, apAssocFailTimesOid)
}

//func RunSnmpRetry(ip, community string, timeout int, ch chan []gosnmp.SnmpPDU, retry int, limitCh chan bool, oid string) {
//
//	var snmpPDUs []gosnmp.SnmpPDU
//	var err error
//	snmpPDUs, err = RunSnmpwalk(ip, community, oid, retry, timeout)
//	if err != nil {
//		log.Println(ip, oid, err)
//		close(ch)
//		<-limitCh
//		return
//	}
//	<-limitCh
//	ch <- snmpPDUs
//
//	return
//}
