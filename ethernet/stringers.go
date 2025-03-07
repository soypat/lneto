// Code generated by "stringer -type=Type -linecomment -output stringers.go ."; DO NOT EDIT.

package ethernet

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[TypeIPv4-2048]
	_ = x[TypeARP-2054]
	_ = x[TypeWakeOnLAN-2114]
	_ = x[TypeTRILL-8947]
	_ = x[TypeDECnetPhase4-24579]
	_ = x[TypeRARP-32821]
	_ = x[TypeAppleTalk-32923]
	_ = x[TypeAARP-33011]
	_ = x[TypeIPX1-33079]
	_ = x[TypeIPX2-33080]
	_ = x[TypeQNXQnet-33284]
	_ = x[TypeIPv6-34525]
	_ = x[TypeEthernetFlowControl-34824]
	_ = x[TypeIEEE802_3-34825]
	_ = x[TypeCobraNet-34841]
	_ = x[TypeMPLSUnicast-34887]
	_ = x[TypeMPLSMulticast-34888]
	_ = x[TypePPPoEDiscovery-34915]
	_ = x[TypePPPoESession-34916]
	_ = x[TypeJumboFrames-34928]
	_ = x[TypeHomePlug1_0MME-34939]
	_ = x[TypeIEEE802_1X-34958]
	_ = x[TypePROFINET-34962]
	_ = x[TypeHyperSCSI-34970]
	_ = x[TypeAoE-34978]
	_ = x[TypeEtherCAT-34980]
	_ = x[TypeEthernetPowerlink-34987]
	_ = x[TypeLLDP-35020]
	_ = x[TypeSERCOS3-35021]
	_ = x[TypeHomePlugAVMME-35041]
	_ = x[TypeMRP-35043]
	_ = x[TypeIEEE802_1AE-35045]
	_ = x[TypeIEEE1588-35063]
	_ = x[TypeIEEE802_1ag-35074]
	_ = x[TypeFCoE-35078]
	_ = x[TypeFCoEInit-35092]
	_ = x[TypeRoCE-35093]
	_ = x[TypeCTP-36864]
	_ = x[TypeVeritasLLT-51966]
	_ = x[TypeVLAN-33024]
	_ = x[TypeServiceVLAN-34984]
}

const _Type_name = "IPv4ARPwake on LANTRILLDECnetPhase4RARPAppleTalkAARPVLANIPx1IPx2QNXQnetIPv6EthernetFlowCtlIEEE802.3CobraNetMPLS UnicastMPLS MulticastPPPoE discoveryPPPoE sessionjumbo frameshome plug 1 0mmeIEEE 802.1xprofinethyper SCSIAoEEtherCATservice VLANEthernet powerlinkLLDPSERCOS3home plug AVMMEMRPIEEE 802.1aeIEEE 1588IEEE 802.1agFCoEFCoE initRoCECTPVeritas LLT"

var _Type_map = map[Type]string{
	2048:  _Type_name[0:4],
	2054:  _Type_name[4:7],
	2114:  _Type_name[7:18],
	8947:  _Type_name[18:23],
	24579: _Type_name[23:35],
	32821: _Type_name[35:39],
	32923: _Type_name[39:48],
	33011: _Type_name[48:52],
	33024: _Type_name[52:56],
	33079: _Type_name[56:60],
	33080: _Type_name[60:64],
	33284: _Type_name[64:71],
	34525: _Type_name[71:75],
	34824: _Type_name[75:90],
	34825: _Type_name[90:99],
	34841: _Type_name[99:107],
	34887: _Type_name[107:119],
	34888: _Type_name[119:133],
	34915: _Type_name[133:148],
	34916: _Type_name[148:161],
	34928: _Type_name[161:173],
	34939: _Type_name[173:189],
	34958: _Type_name[189:200],
	34962: _Type_name[200:208],
	34970: _Type_name[208:218],
	34978: _Type_name[218:221],
	34980: _Type_name[221:229],
	34984: _Type_name[229:241],
	34987: _Type_name[241:259],
	35020: _Type_name[259:263],
	35021: _Type_name[263:270],
	35041: _Type_name[270:285],
	35043: _Type_name[285:288],
	35045: _Type_name[288:300],
	35063: _Type_name[300:309],
	35074: _Type_name[309:321],
	35078: _Type_name[321:325],
	35092: _Type_name[325:334],
	35093: _Type_name[334:338],
	36864: _Type_name[338:341],
	51966: _Type_name[341:352],
}

func (i Type) String() string {
	if str, ok := _Type_map[i]; ok {
		return str
	}
	return "Type(" + strconv.FormatInt(int64(i), 10) + ")"
}
