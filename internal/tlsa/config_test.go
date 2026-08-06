package tlsa

import (
	"errors"
	"reflect"
	"testing"
)

const prefix = "tlsa.example.com"

func ann(kv ...string) map[string]string {
	m := make(map[string]string, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		m[prefix+"/"+kv[i]] = kv[i+1]
	}
	return m
}

func TestParseConfigNotEnabled(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
	}{
		{"no annotations", nil},
		{"empty", map[string]string{}},
		{"enabled false", ann("enabled", "false")},
		{"other annotations only", ann("ports", "25")},
		{"different prefix", map[string]string{"other.example.org/enabled": "true"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig(tc.annotations, prefix)
			if !errors.Is(err, ErrNotEnabled) {
				t.Errorf("err = %v, want ErrNotEnabled", err)
			}
		})
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig(ann("enabled", "true"), prefix)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	want := &Config{
		Enabled:  true,
		Ports:    []int{443},
		Protocol: "tcp",
		TTL:      300,
		Params: Params{
			Usage:        UsageDANEEE,
			Selector:     SelectorSPKI,
			MatchingType: MatchingTypeSHA256,
		},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("config = %+v\nwant %+v", cfg, want)
	}
}

func TestParseConfigFull(t *testing.T) {
	cfg, err := ParseConfig(ann(
		"enabled", "true",
		"ports", "25, 465,587",
		"protocol", "TCP",
		"usage", "DANE-TA",
		"selector", "FullCert",
		"matching-type", "SHA512",
		"ttl", "60",
		"dns-names", "mail.example.com, smtp.example.com",
	), prefix)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}

	if !reflect.DeepEqual(cfg.Ports, []int{25, 465, 587}) {
		t.Errorf("ports = %v", cfg.Ports)
	}
	if cfg.Protocol != "tcp" {
		t.Errorf("protocol = %q, want lowercased tcp", cfg.Protocol)
	}
	if cfg.Params.Usage != UsageDANETA {
		t.Errorf("usage = %v", cfg.Params.Usage)
	}
	if cfg.Params.Selector != SelectorFullCert {
		t.Errorf("selector = %v", cfg.Params.Selector)
	}
	if cfg.Params.MatchingType != MatchingTypeSHA512 {
		t.Errorf("matchingType = %v", cfg.Params.MatchingType)
	}
	if cfg.TTL != 60 {
		t.Errorf("ttl = %d", cfg.TTL)
	}
	if !reflect.DeepEqual(cfg.DNSNames, []string{"mail.example.com", "smtp.example.com"}) {
		t.Errorf("dnsNames = %v", cfg.DNSNames)
	}
}

func TestParseConfigDeduplicatesPorts(t *testing.T) {
	cfg, err := ParseConfig(ann("enabled", "true", "ports", "25,25,443"), prefix)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if !reflect.DeepEqual(cfg.Ports, []int{25, 443}) {
		t.Errorf("ports = %v, want [25 443]", cfg.Ports)
	}
}

func TestParseConfigRejectsBadInput(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
	}{
		{"non-boolean enabled", ann("enabled", "yes please")},
		{"non-numeric port", ann("enabled", "true", "ports", "smtp")},
		{"port zero", ann("enabled", "true", "ports", "0")},
		{"port too large", ann("enabled", "true", "ports", "70000")},
		{"empty ports", ann("enabled", "true", "ports", " , ")},
		{"bad protocol", ann("enabled", "true", "protocol", "quic")},
		{"bad usage", ann("enabled", "true", "usage", "DANE-XX")},
		{"bad selector", ann("enabled", "true", "selector", "pubkey")},
		{"bad matching type", ann("enabled", "true", "matching-type", "md5")},
		{"negative ttl", ann("enabled", "true", "ttl", "-1")},
		{"non-numeric ttl", ann("enabled", "true", "ttl", "5m")},
		{"empty dns-names", ann("enabled", "true", "dns-names", " , ")},
		{"matching type Full is refused", ann("enabled", "true", "matching-type", "Full")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig(tc.annotations, prefix)
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, ErrNotEnabled) {
				t.Fatalf("got ErrNotEnabled, want a validation error: %v", err)
			}
		})
	}
}

// A malformed annotation must never silently fall back to the default, because a
// typo would then publish a record that looks fine and authenticates nothing.
func TestParseConfigDoesNotDefaultOnError(t *testing.T) {
	cfg, err := ParseConfig(ann("enabled", "true", "usage", "DANE-EEE"), prefix)
	if err == nil {
		t.Fatal("expected an error")
	}
	if cfg != nil {
		t.Errorf("config should be nil on error, got %+v", cfg)
	}
}

func TestHasAnyAnnotation(t *testing.T) {
	if !HasAnyAnnotation(ann("ports", "25"), prefix) {
		t.Error("should detect our annotation")
	}
	if HasAnyAnnotation(map[string]string{"other.example.org/ports": "25"}, prefix) {
		t.Error("should not match a different prefix")
	}
	if HasAnyAnnotation(nil, prefix) {
		t.Error("nil annotations should not match")
	}
	// A prefix that is a string prefix of ours must not match.
	if HasAnyAnnotation(map[string]string{"tlsa.example.com.evil.org/ports": "25"}, prefix) {
		t.Error("should not match a prefix-extended domain")
	}
}
