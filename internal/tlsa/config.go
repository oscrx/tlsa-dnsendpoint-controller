package tlsa

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DefaultAnnotationPrefix is the default domain prefix for the annotations this
// controller reads. Override it with --annotation-prefix if you would rather
// use your own domain.
const DefaultAnnotationPrefix = "tlsa.oscarr.nl"

// Annotation suffixes, appended to the configured prefix.
const (
	AnnotationEnabled      = "enabled"
	AnnotationPorts        = "ports"
	AnnotationProtocol     = "protocol"
	AnnotationUsage        = "usage"
	AnnotationSelector     = "selector"
	AnnotationMatchingType = "matching-type"
	AnnotationTTL          = "ttl"
	AnnotationDNSNames     = "dns-names"
)

// Defaults applied when the corresponding annotation is absent. These target
// the most common DANE deployment: an end-entity certificate pinned by public
// key, which is the only combination that supports pre-publication on renewal.
const (
	defaultPort     = 443
	defaultProtocol = "tcp"
	defaultTTL      = int64(300)
)

// Config is the resolved TLSA configuration for one Certificate.
type Config struct {
	// Enabled reports whether TLSA management is opted in for this Certificate.
	Enabled bool
	// Ports are the ports to publish records for.
	Ports []int
	// Protocol is the transport protocol label, almost always "tcp".
	Protocol string
	// Params is the TLSA parameter triple.
	Params Params
	// TTL is the record TTL in seconds.
	TTL int64
	// DNSNames restricts which of the Certificate's DNS names get records.
	// Empty means "every non-wildcard name in spec.dnsNames".
	DNSNames []string
}

// ErrNotEnabled is returned by ParseConfig when the Certificate has not opted in.
var ErrNotEnabled = errors.New("TLSA management not enabled")

// HasAnyAnnotation reports whether any annotation belonging to this controller
// is present. Used to warn about configuration that would otherwise be silently
// ignored because the enabled annotation is missing.
func HasAnyAnnotation(annotations map[string]string, prefix string) bool {
	for k := range annotations {
		if strings.HasPrefix(k, prefix+"/") {
			return true
		}
	}
	return false
}

// ParseConfig resolves the TLSA configuration from a Certificate's annotations.
// It returns ErrNotEnabled if the Certificate has not opted in, and a
// descriptive error if any annotation is malformed. A malformed annotation is
// never silently defaulted: a typo that quietly published the wrong record
// would be worse than publishing nothing.
func ParseConfig(annotations map[string]string, prefix string) (*Config, error) {
	get := func(suffix string) (string, bool) {
		v, ok := annotations[prefix+"/"+suffix]
		return strings.TrimSpace(v), ok
	}

	enabled, ok := get(AnnotationEnabled)
	if !ok {
		return nil, ErrNotEnabled
	}
	on, err := strconv.ParseBool(enabled)
	if err != nil {
		return nil, fmt.Errorf("annotation %s/%s: %q is not a boolean", prefix, AnnotationEnabled, enabled)
	}
	if !on {
		return nil, ErrNotEnabled
	}

	cfg := &Config{
		Enabled:  true,
		Ports:    []int{defaultPort},
		Protocol: defaultProtocol,
		TTL:      defaultTTL,
		Params: Params{
			Usage:        UsageDANEEE,
			Selector:     SelectorSPKI,
			MatchingType: MatchingTypeSHA256,
		},
	}

	if v, ok := get(AnnotationPorts); ok {
		ports, err := parsePorts(v)
		if err != nil {
			return nil, fmt.Errorf("annotation %s/%s: %w", prefix, AnnotationPorts, err)
		}
		cfg.Ports = ports
	}

	if v, ok := get(AnnotationProtocol); ok {
		p := strings.ToLower(v)
		switch p {
		case "tcp", "udp", "sctp":
		default:
			return nil, fmt.Errorf("annotation %s/%s: %q is not one of tcp, udp, sctp", prefix, AnnotationProtocol, v)
		}
		cfg.Protocol = p
	}

	if v, ok := get(AnnotationUsage); ok {
		u, err := ParseUsage(v)
		if err != nil {
			return nil, fmt.Errorf("annotation %s/%s: %w", prefix, AnnotationUsage, err)
		}
		cfg.Params.Usage = u
	}

	if v, ok := get(AnnotationSelector); ok {
		s, err := ParseSelector(v)
		if err != nil {
			return nil, fmt.Errorf("annotation %s/%s: %w", prefix, AnnotationSelector, err)
		}
		cfg.Params.Selector = s
	}

	if v, ok := get(AnnotationMatchingType); ok {
		m, err := ParseMatchingType(v)
		if err != nil {
			return nil, fmt.Errorf("annotation %s/%s: %w", prefix, AnnotationMatchingType, err)
		}
		cfg.Params.MatchingType = m
	}

	if v, ok := get(AnnotationTTL); ok {
		ttl, err := strconv.ParseInt(v, 10, 64)
		if err != nil || ttl < 0 {
			return nil, fmt.Errorf("annotation %s/%s: %q is not a non-negative integer", prefix, AnnotationTTL, v)
		}
		cfg.TTL = ttl
	}

	if v, ok := get(AnnotationDNSNames); ok {
		for _, name := range strings.Split(v, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				cfg.DNSNames = append(cfg.DNSNames, name)
			}
		}
		if len(cfg.DNSNames) == 0 {
			return nil, fmt.Errorf("annotation %s/%s: no DNS names in %q", prefix, AnnotationDNSNames, v)
		}
	}

	// MatchingTypeFull embeds the whole certificate or SPKI in DNS. RFC 7671
	// section 6 recommends against it (large responses, fragmentation) and many
	// providers reject the resulting rdata length, so refuse it rather than
	// produce records that fail to publish.
	if cfg.Params.MatchingType == MatchingTypeFull {
		return nil, fmt.Errorf("annotation %s/%s: Full (0) is not supported; it embeds the entire certificate in DNS and is discouraged by RFC 7671 section 6 — use SHA256 or SHA512",
			prefix, AnnotationMatchingType)
	}

	return cfg, nil
}

func parsePorts(v string) ([]int, error) {
	seen := make(map[int]struct{})
	var ports []int
	for _, field := range strings.Split(v, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		port, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", field)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range 1-65535", port)
		}
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports in %q", v)
	}
	return ports, nil
}
