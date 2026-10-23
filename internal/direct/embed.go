package direct

import _ "embed"

// dlc.dat 来自 v2fly domain-list-community 发布件，与 Java 版内置数据同版本。
//
//go:embed dlc.dat
var dlcData []byte

// ParseDLC 解析内置 geosite 数据。
func ParseDLC(names []string) (map[string][]DomainRule, error) {
	return ParseGeoSite(dlcData, names)
}
