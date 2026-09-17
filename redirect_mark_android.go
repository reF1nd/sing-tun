//go:build android

package tun

// DefaultAutoRedirectResetMark avoids bit 28 (0x10000000), which OEM traffic
// control chains such as Xiaomi HyperOS tc_limiter_OUTPUT write into CONNMARK
// with 0x30000000/0x30000000 on wlan0.
const DefaultAutoRedirectResetMark = 0x00800000
