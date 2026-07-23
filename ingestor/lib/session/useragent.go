package session

import (
	"strings"
)

// Client categories. These drive the UI icon/grouping and are coarser than the
// session type (a single CLI session can carry aws-cli, boto3, and terraform
// clients). "unknown" is the honest fallback for an unrecognized UA — the raw
// string is still retained as a sample, so nothing is lost.
const (
	ClientCategoryCLI     = "cli"     // aws-cli
	ClientCategorySDK     = "sdk"     // boto3/botocore, aws-sdk-*
	ClientCategoryIaC     = "iac"     // terraform, pulumi, cloudformation
	ClientCategoryBrowser = "browser" // web console (Mozilla/Chrome/…)
	ClientCategoryAgent   = "agent"   // claude-code, aws-mcp, Bun, other MCP clients
	ClientCategoryService = "service" // aws-internal / service-to-service
	ClientCategoryUnknown = "unknown"
)

// ParsedClient is the structured identity extracted from one raw user-agent
// string. It is per-event; the aggregator folds many ParsedClients that share a
// Key() into one ClientAggregate. Fields left empty when the UA doesn't carry
// them — the parser never guesses.
type ParsedClient struct {
	Category   string
	Name       string
	Version    string
	OS         string
	OSVersion  string
	Arch       string
	Runtime    string // language runtime, e.g. "python 3.11.6", "Java 17.0.1"
	Command    string // UA-embedded command token, e.g. "s3.cp" (aws-cli only); "" otherwise
	Components map[string]string // single-valued stable extras (awscrt, pyimpl, installer, botocore, terraform_provider_aws)
	Raw        string            // the normalized raw UA, retained as a sample
}

// Key is the client-aggregation key: category|name|version|os|osversion|arch.
// "Name + major identity" — a different version or platform is a different row,
// so the UI can show version/platform drift within one session. Command and
// Components are intentionally excluded (they aggregate *within* a row).
func (p ParsedClient) Key() string {
	return strings.Join([]string{p.Category, p.Name, p.Version, p.OS, p.OSVersion, p.Arch}, "|")
}

// ParseUserAgent turns a raw CloudTrail userAgent into a ParsedClient. The raw
// string is normalized (brackets stripped) first. Recognizes the real formats
// seen in practice: the old positional aws-cli, the new aws-cli md/…#… metadata
// format, Boto3/botocore, aws-sdk-*, Terraform/Pulumi/CloudFormation, browsers,
// and known agents. Unrecognized strings resolve to category "unknown" with the
// leading token as Name.
func ParseUserAgent(rawUA string) ParsedClient {
	raw := NormalizeUserAgent(rawUA)
	p := ParsedClient{Raw: raw, Components: map[string]string{}}
	if raw == "" {
		p.Category = ClientCategoryUnknown
		return p
	}

	lower := strings.ToLower(raw)

	switch {
	case strings.HasPrefix(lower, "aws-cli/"):
		parseAWSCLI(raw, &p)
	case strings.HasPrefix(lower, "boto3/") || strings.HasPrefix(lower, "botocore/"):
		parseBoto(raw, &p)
	case strings.HasPrefix(lower, "aws-sdk-"):
		parseAWSSDK(raw, &p)
	case strings.HasPrefix(lower, "terraform/"):
		parseTerraform(raw, &p)
	case strings.HasPrefix(lower, "pulumi/"):
		p.Category, p.Name, p.Version = ClientCategoryIaC, "pulumi", tokenVersion(raw, "pulumi/")
	case isBrowserUA(lower):
		parseBrowser(raw, &p)
	case strings.Contains(lower, "aws-mcp"):
		p.Category, p.Name = ClientCategoryAgent, "aws-mcp"
	case strings.HasPrefix(lower, "claude-code/"):
		p.Category, p.Name, p.Version = ClientCategoryAgent, "claude-code", tokenVersion(raw, "claude-code/")
	case strings.HasPrefix(lower, "bun/"):
		p.Category, p.Name, p.Version = ClientCategoryAgent, "bun", tokenVersion(raw, "bun/")
	case strings.Contains(lower, "aws-internal"):
		p.Category, p.Name = ClientCategoryService, "aws-internal"
	default:
		// Unknown client: best-effort split of the leading "name/version" token.
		p.Category = ClientCategoryUnknown
		name, ver := splitSlash(leadingToken(raw))
		p.Name = name
		p.Version = trimVersion(ver)
	}

	if len(p.Components) == 0 {
		p.Components = nil
	}
	return p
}

// isBrowserUA matches the console/browser markers already used by
// ClassifySessionType, kept in sync deliberately.
func isBrowserUA(lower string) bool {
	for _, pat := range []string{"mozilla/", "chrome/", "safari/", "firefox/", "edge/", "opera/", "msie", "trident/"} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

// parseAWSCLI handles both aws-cli formats:
//
//	old: aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 source/arm64 prompt/off command/s3.cp
//	new: aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 os/macos#25.2.0 md/arch#arm64 lang/python#3.14.4 md/pyimpl#CPython md/installer#exe md/command#iam.list-users
func parseAWSCLI(raw string, p *ParsedClient) {
	p.Category = ClientCategoryCLI
	p.Name = "aws-cli"
	p.Version = tokenVersion(raw, "aws-cli/")

	for _, tok := range strings.Fields(raw) {
		switch {
		// New metadata format: key#value under md/, os/, lang/ prefixes.
		case strings.HasPrefix(tok, "os/"):
			p.OS, p.OSVersion = splitHash(tok[len("os/"):])
		case strings.HasPrefix(tok, "md/arch#"):
			p.Arch = tok[len("md/arch#"):]
		case strings.HasPrefix(tok, "lang/"):
			lang, ver := splitHash(tok[len("lang/"):])
			p.Runtime = strings.TrimSpace(lang + " " + ver)
		case strings.HasPrefix(tok, "md/command#"):
			p.Command = tok[len("md/command#"):]
		case strings.HasPrefix(tok, "md/pyimpl#"):
			p.Components["pyimpl"] = tok[len("md/pyimpl#"):]
		case strings.HasPrefix(tok, "md/awscrt#"):
			p.Components["awscrt"] = tok[len("md/awscrt#"):]
		case strings.HasPrefix(tok, "md/installer#"):
			p.Components["installer"] = tok[len("md/installer#"):]
		// Old positional format.
		case strings.HasPrefix(tok, "Python/"):
			p.Runtime = "python " + tok[len("Python/"):]
		case strings.HasPrefix(tok, "Darwin/"):
			p.OS, p.OSVersion = "macos", tok[len("Darwin/"):]
		case strings.HasPrefix(tok, "Linux/"):
			p.OS, p.OSVersion = "linux", tok[len("Linux/"):]
		case strings.HasPrefix(tok, "Windows/"):
			p.OS, p.OSVersion = "windows", tok[len("Windows/"):]
		case strings.HasPrefix(tok, "source/"):
			p.Arch = tok[len("source/"):]
		case strings.HasPrefix(tok, "command/"):
			p.Command = tok[len("command/"):]
		}
	}
}

// parseBoto handles Boto3/botocore, incl. the md/…#… metadata tail:
//
//	Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/macos#23.0.0 md/arch#arm64 lang/python#3.11.6
func parseBoto(raw string, p *ParsedClient) {
	p.Category = ClientCategorySDK
	if strings.HasPrefix(strings.ToLower(raw), "boto3/") {
		p.Name, p.Version = "boto3", tokenVersion(raw, "Boto3/")
	} else {
		p.Name, p.Version = "botocore", tokenVersion(raw, "botocore/")
	}
	for _, tok := range strings.Fields(raw) {
		switch {
		case strings.HasPrefix(tok, "os/"):
			p.OS, p.OSVersion = splitHash(tok[len("os/"):])
		case strings.HasPrefix(tok, "md/arch#"):
			p.Arch = tok[len("md/arch#"):]
		case strings.HasPrefix(tok, "lang/"):
			lang, ver := splitHash(tok[len("lang/"):])
			p.Runtime = strings.TrimSpace(lang + " " + ver)
		case strings.HasPrefix(tok, "md/Botocore#"):
			p.Components["botocore"] = tok[len("md/Botocore#"):]
		case strings.HasPrefix(tok, "Python/"):
			p.Runtime = "python " + tok[len("Python/"):]
		}
	}
}

// parseAWSSDK handles aws-sdk-<lang>/<ver> ... e.g.
//
//	aws-sdk-java/2.20.0 Linux/5.10.0 Java/17.0.1
//	pulumi/3.0.0 aws-sdk-go/1.44.0   (leading token wins → this is only reached when aws-sdk leads)
func parseAWSSDK(raw string, p *ParsedClient) {
	p.Category = ClientCategorySDK
	lead := leadingToken(raw) // e.g. "aws-sdk-java/2.20.0"
	name, ver := splitSlash(lead)
	p.Name, p.Version = name, ver
	for _, tok := range strings.Fields(raw) {
		switch {
		case strings.HasPrefix(tok, "Linux/"):
			p.OS, p.OSVersion = "linux", tok[len("Linux/"):]
		case strings.HasPrefix(tok, "Darwin/"):
			p.OS, p.OSVersion = "macos", tok[len("Darwin/"):]
		case strings.HasPrefix(tok, "Windows/"):
			p.OS, p.OSVersion = "windows", tok[len("Windows/"):]
		case strings.HasPrefix(tok, "Java/"):
			p.Runtime = "Java " + tok[len("Java/"):]
		}
	}
}

// parseTerraform handles:
//
//	Terraform/1.6.5 (+https://www.terraform.io) terraform-provider-aws/5.31.0
func parseTerraform(raw string, p *ParsedClient) {
	p.Category = ClientCategoryIaC
	p.Name, p.Version = "terraform", tokenVersion(raw, "Terraform/")
	for _, tok := range strings.Fields(raw) {
		if strings.HasPrefix(tok, "terraform-provider-aws/") {
			p.Components["terraform_provider_aws"] = tok[len("terraform-provider-aws/"):]
		}
	}
}

// parseBrowser extracts name+version+os from a Mozilla UA string. This is a
// pragmatic parse — enough for "Chrome 120 on macOS", not a full UA database.
func parseBrowser(raw string, p *ParsedClient) {
	p.Category = ClientCategoryBrowser
	lower := strings.ToLower(raw)

	// Browser name+version — order matters (Edge/Opera masquerade as Chrome).
	switch {
	case strings.Contains(lower, "edg/") || strings.Contains(lower, "edge/"):
		p.Name = "Edge"
		p.Version = tokenVersionAny(raw, "Edg")
	case strings.Contains(lower, "opr/") || strings.Contains(lower, "opera/"):
		p.Name = "Opera"
		p.Version = tokenVersionAny(raw, "OPR")
	case strings.Contains(lower, "firefox/"):
		p.Name, p.Version = "Firefox", tokenVersionAny(raw, "Firefox")
	case strings.Contains(lower, "chrome/"):
		p.Name, p.Version = "Chrome", tokenVersionAny(raw, "Chrome")
	case strings.Contains(lower, "safari/"):
		p.Name, p.Version = "Safari", tokenVersionAny(raw, "Version")
	default:
		p.Name = "browser"
	}

	switch {
	case strings.Contains(lower, "windows"):
		p.OS = "windows"
	case strings.Contains(lower, "mac os x") || strings.Contains(lower, "macintosh"):
		p.OS = "macos"
	case strings.Contains(lower, "linux"):
		p.OS = "linux"
	case strings.Contains(lower, "android"):
		p.OS = "android"
	case strings.Contains(lower, "iphone") || strings.Contains(lower, "ipad"):
		p.OS = "ios"
	}
}

// --- token helpers ---

// leadingToken returns the first whitespace-delimited token.
func leadingToken(raw string) string {
	tok, _, _ := strings.Cut(raw, " ")
	return tok
}

// splitSlash splits "name/version" → ("name","version"); no slash → (s,"").
func splitSlash(s string) (string, string) {
	name, ver, _ := strings.Cut(s, "/")
	return name, ver
}

// splitHash splits "value#version" → ("value","version"); no hash → (s,"").
func splitHash(s string) (string, string) {
	val, ver, _ := strings.Cut(s, "#")
	return val, ver
}

// tokenVersion returns the version immediately following a known "prefix/" at
// the start of the token that begins with it. E.g. tokenVersion(ua,"aws-cli/").
func tokenVersion(raw, prefix string) string {
	for _, tok := range strings.Fields(raw) {
		if strings.HasPrefix(strings.ToLower(tok), strings.ToLower(prefix)) {
			return trimVersion(tok[len(prefix):])
		}
	}
	return ""
}

// tokenVersionAny finds a token "<name>/<version>" (case-insensitive name) and
// returns the version — for browser tokens like "Chrome/120.0.0.0" that appear
// mid-string.
func tokenVersionAny(raw, name string) string {
	lname := strings.ToLower(name) + "/"
	for _, tok := range strings.Fields(raw) {
		if strings.HasPrefix(strings.ToLower(tok), lname) {
			return trimVersion(tok[len(lname):])
		}
	}
	return ""
}

// trimVersion strips trailing punctuation/parens a version token might carry.
func trimVersion(v string) string {
	return strings.TrimRight(v, ";),")
}
