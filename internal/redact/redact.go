package redact

import "regexp"

type pattern struct {
	name string
	re   *regexp.Regexp
}

var patterns = []pattern{
	{"GH_TOKEN_CLASSIC", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"GH_TOKEN_OAUTH", regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{"GH_TOKEN_SERVER", regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`)},
	{"GH_TOKEN_REFRESH", regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`)},
	{"GH_FINE_GRAINED_PAT", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`)},
	{"AWS_ACCESS_KEY_ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS_SECRET_KEY", regexp.MustCompile(`(?i)(aws_secret_access_key\s*=\s*)[A-Za-z0-9/+]{40}`)},
	{"PEM_PRIVATE_KEY", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

func String(s string) string {
	for _, p := range patterns {
		if p.name == "AWS_SECRET_KEY" {
			s = p.re.ReplaceAllStringFunc(s, func(m string) string {
				loc := p.re.FindStringSubmatchIndex(m)
				if len(loc) >= 4 {
					return m[:loc[2]] + "[REDACTED:AWS_SECRET_KEY]"
				}
				return "[REDACTED:AWS_SECRET_KEY]"
			})
		} else {
			s = p.re.ReplaceAllString(s, "[REDACTED:"+p.name+"]")
		}
	}
	return s
}

func Bytes(b []byte) []byte {
	return []byte(String(string(b)))
}

func HasSecret(s string) bool {
	for _, p := range patterns {
		if p.re.MatchString(s) {
			return true
		}
	}
	return false
}
