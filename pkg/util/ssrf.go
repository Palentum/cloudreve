package util

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

// dangerousIPNets 包含绝对不应被用户URL访问的地址范围。
// 在服务层（请求发出前）校验，涵盖：
// - Loopback、link-local、云实例元数据等高危地址
// - 不包含 RFC 1918 私有网段（10/8、172.16/12、192.168/16），
//   因为合法的从机节点可能部署在内网。
var dangerousIPNets []*net.IPNet

// privateIPNets 包含所有私有/保留地址范围，用于传输层防护 DNS Rebinding。
var privateIPNets []*net.IPNet

func init() {
	dangerousCIDRs := []string{
		// IPv4 — 高危地址
		"0.0.0.0/8",       // 当前网络 (RFC 1122)
		"100.64.0.0/10",   // Carrier-grade NAT (RFC 6598)
		"127.0.0.0/8",     // Loopback (RFC 1122)
		"169.254.0.0/16",  // Link-local / 云实例元数据
		"192.0.0.0/24",    // IETF 协议分配 (RFC 6890)
		"192.0.2.0/24",    // 文档示例 (RFC 5737)
		"198.18.0.0/15",   // 基准测试 (RFC 2544)
		"198.51.100.0/24", // 文档示例 (RFC 5737)
		"203.0.113.0/24",  // 文档示例 (RFC 5737)
		"224.0.0.0/4",     // 多播 (RFC 5771)
		"240.0.0.0/4",     // 保留 (RFC 1112)
		"255.255.255.255/32",

		// IPv6 — 高危地址
		"::1/128",       // Loopback
		"fe80::/10",     // Link-local
		"ff00::/8",      // 多播
		"100::/64",      // 丢弃 (RFC 6666)
		"2001:db8::/32", // 文档示例 (RFC 3849)
	}

	privateCIDRs := []string{
		// 包含上述所有高危地址
		"0.0.0.0/8",
		"10.0.0.0/8",      // 私有网络 (RFC 1918) — 仅传输层拦截
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",    // 私有网络 (RFC 1918) — 仅传输层拦截
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.168.0.0/16",   // 私有网络 (RFC 1918) — 仅传输层拦截
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"255.255.255.255/32",

		// IPv6
		"::1/128",
		"fc00::/7",        // 唯一本地地址 — 仅传输层拦截
		"fe80::/10",
		"ff00::/8",
		"100::/64",
		"2001:db8::/32",
	}

	dangerousIPNets = parseCIDRs(dangerousCIDRs)
	privateIPNets = parseCIDRs(privateCIDRs)
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("ssrf: 内置 CIDR 解析失败 %q: %v", cidr, err))
		}
		nets = append(nets, network)
	}
	return nets
}

// isDangerousIP 检查 IP 是否属于高危地址范围（loopback、link-local、云元数据等）
func isDangerousIP(ip net.IP) bool {
	for _, network := range dangerousIPNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// isPrivateIP 检查 IP 是否属于保留/私有地址范围（含 RFC 1918）
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateIPNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateHostNotPrivate 解析主机名并验证解析后的 IP 不属于高危地址范围
// （loopback、link-local、云元数据等）。
// 不阻止 RFC 1918 私有地址，因为合法从机节点可能部署在内网。
// 返回解析后的 IP 列表，供 NewSSRFSafeTransport 用于 DNS Rebinding 防护。
func ValidateHostNotPrivate(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("无法解析主机名 %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("主机名 %q 未解析到任何地址", host)
	}

	for _, ip := range ips {
		if isDangerousIP(ip) {
			return nil, fmt.Errorf("不允许访问保留网络地址: %s 解析到 %s", host, ip)
		}
	}

	return ips, nil
}

// NewSSRFSafeTransport 返回一个 HTTP Transport，在建立连接前校验目标 IP。
// allowedIPs 为服务层已校验通过的 IP 列表（来自 ValidateHostNotPrivate）。
// DialContext 重新解析 DNS 并验证：
// 1. 解析结果中的 IP 必须在 allowedIPs 中（防 DNS Rebinding / IP 切换）
// 2. 不允许连接到 allowedIPs 之外的私有地址（防绕过）
func NewSSRFSafeTransport(allowedIPs []net.IP) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("无效的地址格式 %q: %w", addr, err)
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			return nil, fmt.Errorf("无法解析主机名 %q: %w", host, err)
		}

		for _, ip := range ips {
			if isPrivateIP(ip) && !containsIP(allowedIPs, ip) {
				return nil, fmt.Errorf("DNS Rebinding 检测: %s 当前解析到 %s, 与初始校验不一致", host, ip)
			}
		}

		return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	return transport
}

// containsIP 检查 IP 列表中是否包含指定 IP
func containsIP(ips []net.IP, target net.IP) bool {
	for _, ip := range ips {
		if ip.Equal(target) {
			return true
		}
	}
	return false
}
