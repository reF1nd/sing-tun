//go:build linux

package tun

import (
	"runtime"
	"strings"
	"testing"
)

func TestValidateAutoRedirectMarks(t *testing.T) {
	t.Parallel()
	defaults := &Options{
		AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
		AutoRedirectOutputMark: DefaultAutoRedirectOutputMark,
		AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
		AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMark,
	}
	if err := validateAutoRedirectMarks(defaults, true); err != nil {
		t.Fatalf("expected distinct defaults to pass, got %v", err)
	}
	colliding := &Options{
		AutoRedirectInputMark:  effectiveMark(0, DefaultAutoRedirectInputMark),
		AutoRedirectOutputMark: effectiveMark(DefaultAutoRedirectResetMark, DefaultAutoRedirectOutputMark),
		AutoRedirectResetMark:  effectiveMark(0, DefaultAutoRedirectResetMark),
		AutoRedirectTProxyMark: effectiveMark(0, DefaultAutoRedirectTProxyMark),
	}
	err := validateAutoRedirectMarks(colliding, false)
	if err == nil {
		t.Fatal("expected colliding output/reset marks to fail validation")
	}
	if !strings.Contains(err.Error(), "auto_redirect_output_mark") || !strings.Contains(err.Error(), "auto_redirect_reset_mark") {
		t.Fatalf("unexpected error message: %v", err)
	}
	outputMatchesTProxy := &Options{
		AutoRedirectInputMark:  DefaultAutoRedirectInputMark,
		AutoRedirectOutputMark: DefaultAutoRedirectTProxyMark,
		AutoRedirectResetMark:  DefaultAutoRedirectResetMark,
		AutoRedirectTProxyMark: DefaultAutoRedirectTProxyMark,
	}
	if err = validateAutoRedirectMarks(outputMatchesTProxy, false); err != nil {
		t.Fatalf("expected output==tproxy to pass when TPROXY is inactive, got %v", err)
	}
	if err = validateAutoRedirectMarks(outputMatchesTProxy, true); err == nil {
		t.Fatal("expected output==tproxy to fail when TPROXY is active")
	}
}

func TestAutoRedirectMarkMaskAndTunFlowMark(t *testing.T) {
	t.Parallel()
	r := &autoRedirect{
		tunOptions: &Options{
			AutoRedirectInputMark:  effectiveMark(0, DefaultAutoRedirectInputMark),
			AutoRedirectOutputMark: effectiveMark(0, DefaultAutoRedirectOutputMark),
			AutoRedirectResetMark:  effectiveMark(0x10000000, DefaultAutoRedirectResetMark),
			AutoRedirectTProxyMark: effectiveMark(0, DefaultAutoRedirectTProxyMark),
		},
	}
	mask := r.effectiveMarkMask()
	tunFlow := r.tunFlowMark()
	if runtime.GOOS == "android" {
		if mask != 0x0c800000 {
			t.Fatalf("got effectiveMarkMask=0x%08x, want 0x0c800000", mask)
		}
		if tunFlow != 0x0c800000 {
			t.Fatalf("got tunFlowMark=0x%08x, want 0x0c800000", tunFlow)
		}
		// Simulate Xiaomi HyperOS tc_limiter_OUTPUT setting 0x30000000 into CONNMARK.
		const vendorBits uint32 = 0x30000000
		if got := (vendorBits | DefaultAutoRedirectTProxyMark) & mask; got != DefaultAutoRedirectTProxyMark {
			t.Fatalf("vendor-tagged tproxy connmark masked to 0x%08x, want 0x%08x", got, DefaultAutoRedirectTProxyMark)
		}
		if got := (vendorBits | DefaultAutoRedirectOutputMark) & mask; got != DefaultAutoRedirectOutputMark {
			t.Fatalf("vendor-tagged output connmark masked to 0x%08x, want 0x%08x", got, DefaultAutoRedirectOutputMark)
		}
	} else {
		if mask != 0x1c000000 {
			t.Fatalf("got effectiveMarkMask=0x%08x, want 0x1c000000", mask)
		}
		if tunFlow != 0x1c000000 {
			t.Fatalf("got tunFlowMark=0x%08x, want 0x1c000000", tunFlow)
		}
	}
}
