package direct

import (
	"errors"
	"strings"
)

// geosite 规则类型，与 v2fly domain-list-community 的 Domain.type 一致。
const (
	TypeKeyword = 0 // 主机名包含子串
	TypeRegexp  = 1 // 主机名匹配正则（部分匹配语义）
	TypeDomain  = 2 // 匹配该域名的任意子域
	TypeFull    = 3 // 完整域名精确匹配
)

// protobuf wire tag：GeoSiteList.entry / GeoSite.country_code / GeoSite.domain /
// Domain.type / Domain.value
const (
	entryTag  = 1<<3 | 2
	codeTag   = 1<<3 | 2
	domainTag = 2<<3 | 2
	typeTag   = 1<<3 | 0
	valueTag  = 2<<3 | 2
)

var errMalformed = errors.New("非法dlc.dat")

// DomainRule 一条 geosite 域名规则。
type DomainRule struct {
	Type  int
	Value string
}

// ParseGeoSite 解析 dlc.dat（protobuf 编码的 GeoSiteList），只收集 names 指定的列表。
// 非目标列表在读到列表名后整体跳过，避免全量展开占用内存。
func ParseGeoSite(data []byte, names []string) (map[string][]DomainRule, error) {
	wanted := make(map[string]struct{}, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			wanted[n] = struct{}{}
		}
	}
	res := make(map[string][]DomainRule)
	if len(wanted) == 0 {
		return res, nil
	}

	r := &geoReader{buf: data}
	for r.pos < len(r.buf) {
		tag, err := r.varint()
		if err != nil {
			return nil, err
		}
		if tag != entryTag {
			if err := r.skip(tag); err != nil {
				return nil, err
			}
			continue
		}
		n, err := r.length()
		if err != nil {
			return nil, err
		}
		end := r.pos + n
		if err := parseEntry(r, end, wanted, res); err != nil {
			return nil, err
		}
		r.pos = end
	}
	return res, nil
}

func parseEntry(r *geoReader, end int, wanted map[string]struct{}, res map[string][]DomainRule) error {
	var code string
	hasCode := false
	var rules []DomainRule
	for r.pos < end {
		tag, err := r.varint()
		if err != nil {
			return err
		}
		switch tag {
		case codeTag:
			s, err := r.str()
			if err != nil {
				return err
			}
			// dlc.dat 内列表名为全大写，统一小写后比较
			code, hasCode = strings.ToLower(s), true
		case domainTag:
			if hasCode {
				if _, ok := wanted[code]; !ok {
					r.pos = end
					return nil
				}
			}
			n, err := r.length()
			if err != nil {
				return err
			}
			end := r.pos + n
			rule, ok, err := parseDomain(r, end)
			if err != nil {
				return err
			}
			// parseDomain 已消费到 end，此处仅作容错对齐，避免游标漂移
			r.pos = end
			if ok {
				rules = append(rules, rule)
			}
		default:
			if err := r.skip(tag); err != nil {
				return err
			}
		}
	}
	if _, ok := wanted[code]; hasCode && ok && len(rules) > 0 {
		res[code] = rules
	}
	return nil
}

func parseDomain(r *geoReader, end int) (DomainRule, bool, error) {
	rule := DomainRule{Type: TypeKeyword}
	value := ""
	for r.pos < end {
		tag, err := r.varint()
		if err != nil {
			return rule, false, err
		}
		switch tag {
		case typeTag:
			v, err := r.varint()
			if err != nil {
				return rule, false, err
			}
			rule.Type = int(v)
		case valueTag:
			s, err := r.str()
			if err != nil {
				return rule, false, err
			}
			value = s
		default:
			if err := r.skip(tag); err != nil {
				return rule, false, err
			}
		}
	}
	if value == "" {
		return rule, false, nil
	}
	rule.Value = value
	return rule, true, nil
}

// geoReader 最小 wire-format 读取器：varint / 长度前缀 / 定长跳过。
type geoReader struct {
	buf []byte
	pos int
}

func (r *geoReader) varint() (uint64, error) {
	var v uint64
	for shift := uint(0); shift < 64; shift += 7 {
		if r.pos >= len(r.buf) {
			return 0, errMalformed
		}
		b := r.buf[r.pos]
		r.pos++
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errMalformed
}

func (r *geoReader) length() (int, error) {
	v, err := r.varint()
	if err != nil {
		return 0, err
	}
	if v > uint64(len(r.buf)) || r.pos+int(v) > len(r.buf) {
		return 0, errMalformed
	}
	return int(v), nil
}

func (r *geoReader) str() (string, error) {
	n, err := r.length()
	if err != nil {
		return "", err
	}
	s := string(r.buf[r.pos : r.pos+n])
	r.pos += n
	return s, nil
}

func (r *geoReader) skip(tag uint64) error {
	switch tag & 7 {
	case 0:
		_, err := r.varint()
		return err
	case 1:
		r.pos += 8
	case 2:
		n, err := r.length()
		if err != nil {
			return err
		}
		r.pos += n
	case 5:
		r.pos += 4
	default:
		// group 类型已废弃，dlc.dat 不会出现；返回错误避免游标不前进导致死循环
		return errMalformed
	}
	if r.pos > len(r.buf) {
		return errMalformed
	}
	return nil
}
