package util

import (
	"net"
	"testing"
)

func TestIsDangerousIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// 高危地址 — 应被阻止
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"loopback 127.0.0.2", "127.0.0.2", true},
		{"link-local 169.254.169.254", "169.254.169.254", true},
		{"link-local 169.254.0.1", "169.254.0.1", true},
		{"current network 0.0.0.0", "0.0.0.0", true},
		{"CGNAT 100.64.0.1", "100.64.0.1", true},
		{"multicast 224.0.0.1", "224.0.0.1", true},
		{"reserved 240.0.0.1", "240.0.0.1", true},
		{"broadcast 255.255.255.255", "255.255.255.255", true},
		{"benchmark 198.18.0.1", "198.18.0.1", true},
		{"doc example 192.0.2.1", "192.0.2.1", true},
		{"doc example 198.51.100.1", "198.51.100.1", true},
		{"doc example 203.0.113.1", "203.0.113.1", true},

		// IPv6 高危地址
		{"IPv6 loopback", "::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 multicast", "ff02::1", true},
		{"IPv6 discard", "100::1", true},
		{"IPv6 doc example", "2001:db8::1", true},

		// 内网地址 — 服务层允许（合法从机可能在内网）
		{"RFC1918 10.0.0.1", "10.0.0.1", false},
		{"RFC1918 10.255.255.255", "10.255.255.255", false},
		{"RFC1918 172.16.0.1", "172.16.0.1", false},
		{"RFC1918 172.31.255.255", "172.31.255.255", false},
		{"RFC1918 192.168.0.1", "192.168.0.1", false},
		{"RFC1918 192.168.255.255", "192.168.255.255", false},
		{"IPv6 ULA", "fc00::1", false},
		{"IPv6 ULA fd", "fd00::1", false},

		// 公网地址 — 应被允许
		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 104.16.0.1", "104.16.0.1", false},
		{"public 11.0.0.1", "11.0.0.1", false},
		{"public 100.0.0.1", "100.0.0.1", false},
		{"public 172.15.0.1", "172.15.0.1", false},
		{"public 172.32.0.1", "172.32.0.1", false},
		{"public 193.0.0.1", "193.0.0.1", false},
		{"IPv6 public", "2606:4700::1", false},
		{"IPv6 public 2", "2001:4860:4860::8888", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("无法解析测试 IP: %s", tt.ip)
			}
			result := isDangerousIP(ip)
			if result != tt.expected {
				t.Errorf("isDangerousIP(%s) = %v, 期望 %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"loopback 127.0.0.1", "127.0.0.1", true},
		{"RFC1918 10.0.0.1", "10.0.0.1", true},
		{"RFC1918 172.16.0.1", "172.16.0.1", true},
		{"RFC1918 192.168.0.1", "192.168.0.1", true},
		{"link-local 169.254.169.254", "169.254.169.254", true},
		{"CGNAT 100.64.0.1", "100.64.0.1", true},
		{"current network 0.0.0.0", "0.0.0.0", true},
		{"multicast 224.0.0.1", "224.0.0.1", true},
		{"reserved 240.0.0.1", "240.0.0.1", true},
		{"broadcast 255.255.255.255", "255.255.255.255", true},
		{"IPv6 loopback", "::1", true},
		{"IPv6 link-local", "fe80::1", true},
		{"IPv6 ULA", "fc00::1", true},
		{"IPv6 ULA fd", "fd00::1", true},
		{"IPv6 multicast", "ff02::1", true},

		{"public 8.8.8.8", "8.8.8.8", false},
		{"public 1.1.1.1", "1.1.1.1", false},
		{"public 11.0.0.1", "11.0.0.1", false},
		{"public 100.0.0.1", "100.0.0.1", false},
		{"public 172.15.0.1", "172.15.0.1", false},
		{"public 172.32.0.1", "172.32.0.1", false},
		{"public 193.0.0.1", "193.0.0.1", false},
		{"IPv6 public", "2606:4700::1", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("无法解析测试 IP: %s", tt.ip)
			}
			result := isPrivateIP(ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%s) = %v, 期望 %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestValidateHostNotPrivate(t *testing.T) {
	// 高危地址 — 应返回错误
	t.Run("loopback localhost", func(t *testing.T) {
		_, err := ValidateHostNotPrivate("localhost")
		if err == nil {
			t.Error("localhost (127.0.0.1) 应被拒绝")
		}
	})

	t.Run("metadata IP literal", func(t *testing.T) {
		_, err := ValidateHostNotPrivate("169.254.169.254")
		if err == nil {
			t.Error("169.254.169.254 应被拒绝")
		}
	})

	t.Run("loopback IP literal", func(t *testing.T) {
		_, err := ValidateHostNotPrivate("127.0.0.2")
		if err == nil {
			t.Error("127.0.0.2 应被拒绝")
		}
	})

	// 内网地址 — 服务层应允许并返回解析结果
	t.Run("RFC1918 192.168.x returns IPs", func(t *testing.T) {
		ips, err := ValidateHostNotPrivate("192.168.1.1")
		if err != nil {
			t.Fatalf("192.168.1.1 应被允许, 得到错误: %v", err)
		}
		if len(ips) == 0 {
			t.Fatal("应返回解析后的 IP 列表")
		}
		if !ips[0].Equal(net.ParseIP("192.168.1.1")) {
			t.Errorf("期望 192.168.1.1, 得到 %s", ips[0])
		}
	})

	t.Run("RFC1918 10.x returns IPs", func(t *testing.T) {
		ips, err := ValidateHostNotPrivate("10.0.0.1")
		if err != nil {
			t.Fatalf("10.0.0.1 应被允许, 得到错误: %v", err)
		}
		if len(ips) == 0 {
			t.Fatal("应返回解析后的 IP 列表")
		}
	})

	t.Run("RFC1918 172.16.x returns IPs", func(t *testing.T) {
		ips, err := ValidateHostNotPrivate("172.16.0.1")
		if err != nil {
			t.Fatalf("172.16.0.1 应被允许, 得到错误: %v", err)
		}
		if len(ips) == 0 {
			t.Fatal("应返回解析后的 IP 列表")
		}
	})

	// 无法解析的主机 — 应返回错误
	t.Run("unresolvable host", func(t *testing.T) {
		_, err := ValidateHostNotPrivate("this-host-does-not-exist-ssrf-test.invalid")
		if err == nil {
			t.Error("无法解析的主机应返回错误")
		}
	})
}

func TestContainsIP(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
	}

	t.Run("match IPv4", func(t *testing.T) {
		if !containsIP(ips, net.ParseIP("192.168.1.1")) {
			t.Error("应找到 192.168.1.1")
		}
	})

	t.Run("no match", func(t *testing.T) {
		if containsIP(ips, net.ParseIP("192.168.1.2")) {
			t.Error("不应找到 192.168.1.2")
		}
	})

	t.Run("empty list", func(t *testing.T) {
		if containsIP(nil, net.ParseIP("192.168.1.1")) {
			t.Error("空列表中不应找到任何 IP")
		}
	})

	t.Run("IPv4-mapped IPv6 matches IPv4", func(t *testing.T) {
		v4 := net.ParseIP("192.168.1.1")
		v4mapped := net.ParseIP("::ffff:192.168.1.1")
		if !containsIP([]net.IP{v4}, v4mapped) {
			t.Error("IPv4-mapped IPv6 应匹配对应的 IPv4")
		}
	})
}
