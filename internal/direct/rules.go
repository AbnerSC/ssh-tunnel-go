package direct

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"git.edge.05200809.xyz/dengming/ssh-tunnel-go/internal/logging"
)

var (
	ipv4Shape = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
	ipv6Shape = regexp.MustCompile(`^[0-9A-Fa-f:]+$`)
)

// Rules 直连路由规则：命中任一规则的目标由本地直接访问，不经过远程 SSH 代理。
type Rules struct {
	ips      map[netip.Addr]struct{}
	prefixes []netip.Prefix
	domains  map[string]struct{} // 主域匹配
	full     map[string]struct{} // 完整匹配
	keywords []string
	regexps  []*regexp.Regexp
	// force 强制走隧道的主域（含子域），优先级高于上面全部直连规则
	force map[string]struct{}
}

// New 根据直连 IP 与域名配置构建规则；单个值内可用逗号/分号/空白分隔多个规则。
func New(directIPs, directDomains []string) *Rules {
	r := &Rules{
		ips:     make(map[netip.Addr]struct{}),
		domains: make(map[string]struct{}),
		full:    make(map[string]struct{}),
		force:   make(map[string]struct{}),
	}
	for _, item := range directIPs {
		for _, part := range splitMulti(item) {
			r.addIP(part)
		}
	}
	for _, item := range directDomains {
		for _, part := range splitMulti(item) {
			r.addDomain(part)
		}
	}
	return r
}

// IsDirect 判断目标主机是否命中直连规则。host 可以是域名、IPv4 或 IPv6 字面量。
func (r *Rules) IsDirect(host string) bool {
	if r == nil {
		return false
	}
	str := strings.TrimSpace(host)
	if str == "" {
		return false
	}
	if addr, ok := parseIPLiteral(str); ok {
		if _, found := r.ips[addr]; found {
			return true
		}
		for _, prefix := range r.prefixes {
			if prefix.Contains(addr) {
				return true
			}
		}
		// IP 目标不参与域名规则匹配（与 Java 版一致）
		return false
	}

	// 域名匹配，按成本从低到高：强制走隧道 → full 精确 → 主域 → 关键字 → 正则
	lower := stripTailDot(strings.ToLower(str))
	// 强制走隧道优先：国内域名列表常收进国际服务的 .cn 镜像域名
	// （如 geosite:cn 含 googleapis.cn），命中后会把 Play 的
	// services.googleapis.cn 拉到本地直连，下载链路随之失效
	if r.isForce(lower) {
		return false
	}
	if _, ok := r.full[lower]; ok {
		return true
	}
	if _, ok := r.domains[lower]; ok {
		return true
	}
	suffix := lower
	for {
		idx := strings.IndexByte(suffix, '.')
		if idx < 0 {
			break
		}
		suffix = suffix[idx+1:]
		if _, ok := r.domains[suffix]; ok {
			return true
		}
	}
	for _, keyword := range r.keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	for _, re := range r.regexps {
		if re.MatchString(lower) {
			return true
		}
	}
	return false
}

// Empty 是否没有任何规则。
func (r *Rules) Empty() bool {
	if r == nil {
		return true
	}
	return len(r.ips) == 0 && len(r.prefixes) == 0 && len(r.domains) == 0 &&
		len(r.full) == 0 && len(r.keywords) == 0 && len(r.regexps) == 0 && len(r.force) == 0
}

// SetForceDomains 设置强制走隧道的域名（主域匹配，含子域）。
//
// 用于抵消直连规则的误伤：-direct-cn 内置的 geosite:cn 会命中
// googleapis.cn / google.cn / gstatic.cn 等 Google 中国域名，
// 这些域名一旦直连，Google Play 的更新下载会指向国内不可用的地址。
func (r *Rules) SetForceDomains(values []string) {
	if r == nil {
		return
	}
	if r.force == nil {
		r.force = make(map[string]struct{})
	}
	for _, item := range values {
		for _, part := range splitMulti(item) {
			lower := stripTailDot(strings.ToLower(stripQuote(part)))
			if lower == "" || strings.ContainsRune(lower, '/') {
				logging.Warn("direct", "忽略非法强制隧道域名", "value", part)
				continue
			}
			r.force[lower] = struct{}{}
		}
	}
}

// ForceDomainCount 强制走隧道的域名数量。
func (r *Rules) ForceDomainCount() int {
	if r == nil {
		return 0
	}
	return len(r.force)
}

// isForce 判断域名是否命中强制走隧道规则（主域后缀匹配）。
func (r *Rules) isForce(name string) bool {
	if len(r.force) == 0 {
		return false
	}
	if _, ok := r.force[name]; ok {
		return true
	}
	suffix := name
	for {
		idx := strings.IndexByte(suffix, '.')
		if idx < 0 {
			return false
		}
		suffix = suffix[idx+1:]
		if _, ok := r.force[suffix]; ok {
			return true
		}
	}
}

// IPRuleCount IP 规则数量（含网段）。
func (r *Rules) IPRuleCount() int {
	if r == nil {
		return 0
	}
	return len(r.ips) + len(r.prefixes)
}

// DomainRuleCount 域名规则数量。
func (r *Rules) DomainRuleCount() int {
	if r == nil {
		return 0
	}
	return len(r.domains) + len(r.full) + len(r.keywords) + len(r.regexps)
}

// AddGeoSite 追加 geosite 域名规则。
func (r *Rules) AddGeoSite(rules []DomainRule) {
	for _, rule := range rules {
		value := strings.ToLower(strings.TrimSpace(rule.Value))
		if value == "" {
			continue
		}
		switch rule.Type {
		case TypeDomain:
			r.domains[stripTailDot(value)] = struct{}{}
		case TypeFull:
			r.full[stripTailDot(value)] = struct{}{}
		case TypeKeyword:
			r.keywords = append(r.keywords, value)
		case TypeRegexp:
			re, err := regexp.Compile(value)
			if err != nil {
				// Go RE2 不支持后向引用/环视等语法，忽略这类规则并记录日志
				logging.Warn("direct", "忽略不兼容的geosite正则", "rule", value, "err", err)
				continue
			}
			r.regexps = append(r.regexps, re)
		default:
			logging.Warn("direct", "忽略未知geosite规则类型", "type", rule.Type, "value", value)
		}
	}
}

func (r *Rules) addIP(item string) {
	str := stripQuote(item)
	if str == "" {
		return
	}
	slash := strings.IndexByte(str, '/')
	if slash < 0 {
		addr, ok := parseIPLiteral(str)
		if !ok {
			logging.Warn("direct", "忽略非法直连IP", "value", str)
			return
		}
		r.ips[addr] = struct{}{}
		return
	}
	addr, ok := parseIPLiteral(str[:slash])
	if !ok {
		logging.Warn("direct", "忽略非法直连网段", "value", str)
		return
	}
	prefix, ok := parsePrefix(str[slash+1:], addr.BitLen())
	if !ok {
		logging.Warn("direct", "忽略非法直连网段", "value", str)
		return
	}
	r.prefixes = append(r.prefixes, netip.PrefixFrom(addr, prefix).Masked())
}

func (r *Rules) addDomain(item string) {
	str := stripQuote(item)
	if str == "" {
		return
	}
	lower := stripTailDot(strings.ToLower(str))
	if lower == "" {
		return
	}
	// 容错：误把 IP 塞进域名配置时按 IP 规则处理
	if addr, ok := parseIPLiteral(lower); ok {
		r.ips[addr] = struct{}{}
		return
	}
	if strings.ContainsRune(lower, '/') {
		logging.Warn("direct", "忽略非法直连域名", "value", str)
		return
	}
	r.domains[lower] = struct{}{}
}

// parsePrefix 解析前缀长度：支持 24 与 255.255.255.0 两种写法。
func parsePrefix(mask string, maxBits int) (int, bool) {
	if strings.ContainsRune(mask, '.') {
		addr, ok := parseIPLiteral(mask)
		if !ok || !addr.Is4() {
			return 0, false
		}
		bytes := addr.As4()
		prefix := 0
		zeroSeen := false
		for _, b := range bytes {
			for i := 7; i >= 0; i-- {
				if b>>i&1 == 1 {
					if zeroSeen {
						return 0, false
					}
					prefix++
				} else {
					zeroSeen = true
				}
			}
		}
		return prefix, prefix <= maxBits
	}
	n, err := strconv.Atoi(mask)
	if err != nil || n < 0 || n > maxBits {
		return 0, false
	}
	return n, true
}

// parseIPLiteral 仅解析 IP 字面量，非字面量返回 false（不触发 DNS 解析）。
func parseIPLiteral(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	if strings.ContainsRune(s, ':') {
		if !ipv6Shape.MatchString(s) {
			return netip.Addr{}, false
		}
	} else if !ipv4Shape.MatchString(s) {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

func splitMulti(item string) []string {
	str := stripQuote(item)
	if str == "" {
		return nil
	}
	return strings.FieldsFunc(str, func(c rune) bool {
		return c == ',' || c == '，' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n'
	})
}

func stripTailDot(s string) string {
	return strings.TrimSuffix(s, ".")
}

func stripQuote(s string) string {
	s = strings.TrimSpace(s)
	for len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			s = strings.TrimSpace(s[1 : len(s)-1])
			continue
		}
		break
	}
	return s
}
