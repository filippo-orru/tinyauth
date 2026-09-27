package utils

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/tinyauthapp/tinyauth/pkg/validators"
)

var (
	ErrFilterEmpty = errors.New("filter is empty")
)

func GetSecret(conf string, file string) string {
	if conf == "" && file == "" {
		return ""
	}

	if conf != "" {
		return conf
	}

	contents, err := ReadFile(file)
	if err != nil {
		return ""
	}

	return ParseSecretFile(contents)
}

func ParseSecretFile(contents string) string {
	lines := strings.Split(contents, "\n")

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		return strings.TrimSpace(line)
	}

	return ""
}

func EncodeBasicAuth(username string, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func CheckIPFilter(filter string, ip string) (bool, error) {
	ipAddr := net.ParseIP(ip)

	if ipAddr == nil {
		return false, fmt.Errorf("invalid ip address")
	}

	filter = strings.ReplaceAll(filter, "-", "/")

	if strings.Contains(filter, "/") {
		_, cidr, err := net.ParseCIDR(filter)
		if err != nil {
			return false, fmt.Errorf("invalid cidr notation: %w", err)
		}
		return cidr.Contains(ipAddr), nil
	}

	ipFilter := net.ParseIP(filter)

	if ipFilter == nil {
		return false, fmt.Errorf("invalid ip address")
	}

	if ipFilter.Equal(ipAddr) {
		return true, nil
	}

	return false, nil
}

func CheckFilter(filter string, input string) (bool, error) {
	if len(strings.TrimSpace(filter)) == 0 {
		return false, ErrFilterEmpty
	}

	if strings.HasPrefix(filter, "/") && strings.HasSuffix(filter, "/") {
		re, err := regexp.Compile(filter[1 : len(filter)-1])
		if err != nil {
			return false, fmt.Errorf("invalid regex filter: %w", err)
		}

		if re.MatchString(input) {
			return true, nil
		}
	}

	for item := range strings.SplitSeq(filter, ",") {
		if strings.TrimSpace(item) == input {
			return true, nil
		}
	}

	return false, nil
}

func GenerateUUID(str string) string {
	uuid := uuid.NewSHA1(uuid.NameSpaceURL, []byte(str))
	return uuid.String()
}

// GetSessionCookieDomain returns the cookie domain to use for session cookies given the static config and runtime config,
// falling back to an empty string (host-only cookie) when subdomains are not enabled.
func GetSessionCookieDomain(config *model.Config, runtime *model.RuntimeConfig) string {
	if !config.Auth.SubdomainsEnabled {
		return ""
	}
	return runtime.CookieDomain
}

// IsRedirectSafe checks that the given redirect URI is either the configured app URL or,
// when subdomains are enabled, a subdomain of the configured cookie domain.
func IsRedirectSafe(config *model.Config, runtime *model.RuntimeConfig, log *logger.Logger, redirectURI string) bool {
	v := validators.NewDomainValidator(validators.DomainValidatorOptions{
		WithPort:       true,
		WithScheme:     true,
		AllowedSchemes: []string{"https", "http"},
	})

	_, err := v.SafeHostname(runtime.AppURL)

	if err != nil {
		log.App.Error().Err(err).Msg("App URL is invalid, cannot validate redirect URI")
		return false
	}

	err = v.Validate(redirectURI, runtime.AppURL)

	if err == nil {
		return true
	}

	log.App.Debug().Err(err).Msg("Failed to validate redirect URI")

	if !errors.Is(err, validators.ErrHostnameMismatch) {
		return false
	}

	if !config.Auth.SubdomainsEnabled {
		return false
	}

	v = validators.NewDomainValidator(validators.DomainValidatorOptions{})

	hostname, err := v.SafeHostname(redirectURI)

	if err != nil {
		log.App.Error().Err(err).Msg("Failed to get safe hostname from redirect URI")
		return false
	}

	if strings.HasSuffix(hostname, "."+strings.ToLower(runtime.CookieDomain)) ||
		hostname == runtime.CookieDomain {
		return true
	}

	return false
}

func GenerateString(length int) string {
	src := make([]byte, length)
	rand.Read(src)
	return base64.RawURLEncoding.EncodeToString(src)[:length]
}
