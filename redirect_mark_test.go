package tun

import (
	"runtime"
	"testing"
)

func TestAutoRedirectDefaultMarks(t *testing.T) {
	t.Parallel()
	const xiaomiTCLimiterMask uint32 = 0x30000000
	if androidReservedMarkMask&0x10000000 == 0 {
		t.Fatalf("androidReservedMarkMask (0x%08x) must reserve bit 28 (0x10000000)", androidReservedMarkMask)
	}
	if androidReservedMarkMask&0x00800000 != 0 {
		t.Fatalf("androidReservedMarkMask (0x%08x) must not reserve bit 23 (0x00800000)", androidReservedMarkMask)
	}
	androidDefaultMask := uint32(DefaultAutoRedirectInputMark | DefaultAutoRedirectOutputMark | 0x00800000 | DefaultAutoRedirectTProxyMark)
	if androidDefaultMask&androidReservedMarkMask != 0 {
		t.Fatalf("Android default mark mask 0x%08x overlaps androidReservedMarkMask 0x%08x", androidDefaultMask, androidReservedMarkMask)
	}
	if androidDefaultMask&xiaomiTCLimiterMask != 0 {
		t.Fatalf("Android default mark mask 0x%08x overlaps OEM tc_limiter mask 0x%08x", androidDefaultMask, xiaomiTCLimiterMask)
	}
	if runtime.GOOS == "android" {
		if DefaultAutoRedirectResetMark != 0x00800000 {
			t.Fatalf("got DefaultAutoRedirectResetMark=0x%08x, want 0x00800000", DefaultAutoRedirectResetMark)
		}
		if got := effectiveMark(0, DefaultAutoRedirectResetMark); got != 0x00800000 {
			t.Fatalf("effectiveMark(0) = 0x%08x, want 0x00800000", got)
		}
		if got := effectiveMark(0x10000000, DefaultAutoRedirectResetMark); got != 0x00800000 {
			t.Fatalf("effectiveMark(0x10000000) = 0x%08x, want 0x00800000", got)
		}
		if got := effectiveMark(0x14000000, DefaultAutoRedirectInputMark); got != DefaultAutoRedirectInputMark {
			t.Fatalf("effectiveMark(0x14000000) = 0x%08x, want 0x%08x", got, DefaultAutoRedirectInputMark)
		}
		if got := effectiveMark(0x00400000, DefaultAutoRedirectResetMark); got != 0x00400000 {
			t.Fatalf("effectiveMark(0x00400000) = 0x%08x, want 0x00400000", got)
		}
	} else {
		if DefaultAutoRedirectResetMark != 0x10000000 {
			t.Fatalf("got DefaultAutoRedirectResetMark=0x%08x, want 0x10000000", DefaultAutoRedirectResetMark)
		}
		if got := effectiveMark(0x10000000, DefaultAutoRedirectResetMark); got != 0x10000000 {
			t.Fatalf("effectiveMark(0x10000000) = 0x%08x, want 0x10000000", got)
		}
	}
}
