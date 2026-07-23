package session

import (
	"testing"
)

func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name         string
		ua           string
		wantCategory string
		wantName     string
		wantVersion  string
		wantOS       string
		wantOSVer    string
		wantArch     string
		wantRuntime  string
		wantCommand  string
		wantComp     map[string]string
	}{
		{
			name:         "aws-cli old positional format with command",
			ua:           "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 source/arm64 prompt/off command/s3.cp",
			wantCategory: ClientCategoryCLI,
			wantName:     "aws-cli",
			wantVersion:  "2.15.0",
			wantOS:       "macos",
			wantOSVer:    "23.0.0",
			wantArch:     "arm64",
			wantRuntime:  "python 3.11.6",
			wantCommand:  "s3.cp",
		},
		{
			name:         "aws-cli old positional format without command",
			ua:           "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 source/arm64",
			wantCategory: ClientCategoryCLI,
			wantName:     "aws-cli",
			wantVersion:  "2.15.0",
			wantOS:       "macos",
			wantOSVer:    "23.0.0",
			wantArch:     "arm64",
			wantRuntime:  "python 3.11.6",
			wantCommand:  "",
		},
		{
			name:         "aws-cli new md metadata format",
			ua:           "aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 os/macos#25.2.0 md/arch#arm64 lang/python#3.14.4 md/pyimpl#CPython m/AC,AD,Z,E,C,b cfg/retry-mode#standard md/installer#exe sid/0ce22194f7b7 md/prompt#off md/command#iam.list-users",
			wantCategory: ClientCategoryCLI,
			wantName:     "aws-cli",
			wantVersion:  "2.34.30",
			wantOS:       "macos",
			wantOSVer:    "25.2.0",
			wantArch:     "arm64",
			wantRuntime:  "python 3.14.4",
			wantCommand:  "iam.list-users",
			wantComp:     map[string]string{"awscrt": "0.31.2", "pyimpl": "CPython", "installer": "exe"},
		},
		{
			name:         "aws-cli new md format bracketed (sso testdata)",
			ua:           "[aws-cli/2.34.30 md/awscrt#0.31.2 ua/2.1 os/macos#25.2.0 md/arch#arm64 lang/python#3.14.4 md/pyimpl#CPython m/u,Z,E,C,t,b cfg/retry-mode#standard md/installer#exe sid/e15370b661ab md/prompt#off md/command#s3.ls]",
			wantCategory: ClientCategoryCLI,
			wantName:     "aws-cli",
			wantVersion:  "2.34.30",
			wantOS:       "macos",
			wantOSVer:    "25.2.0",
			wantArch:     "arm64",
			wantRuntime:  "python 3.14.4",
			wantCommand:  "s3.ls",
			wantComp:     map[string]string{"awscrt": "0.31.2", "pyimpl": "CPython", "installer": "exe"},
		},
		{
			name:         "boto3 with md metadata",
			ua:           "Boto3/1.34.0 md/Botocore#1.34.0 ua/2.0 os/macos#23.0.0 md/arch#arm64 lang/python#3.11.6",
			wantCategory: ClientCategorySDK,
			wantName:     "boto3",
			wantVersion:  "1.34.0",
			wantOS:       "macos",
			wantOSVer:    "23.0.0",
			wantArch:     "arm64",
			wantRuntime:  "python 3.11.6",
			wantComp:     map[string]string{"botocore": "1.34.0"},
		},
		{
			name:         "terraform with aws provider",
			ua:           "Terraform/1.6.5 (+https://www.terraform.io) terraform-provider-aws/5.31.0",
			wantCategory: ClientCategoryIaC,
			wantName:     "terraform",
			wantVersion:  "1.6.5",
			wantComp:     map[string]string{"terraform_provider_aws": "5.31.0"},
		},
		{
			name:         "aws-sdk-java",
			ua:           "aws-sdk-java/2.20.0 Linux/5.10.0 Java/17.0.1",
			wantCategory: ClientCategorySDK,
			wantName:     "aws-sdk-java",
			wantVersion:  "2.20.0",
			wantOS:       "linux",
			wantOSVer:    "5.10.0",
			wantRuntime:  "Java 17.0.1",
		},
		{
			name:         "chrome on macOS",
			ua:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantCategory: ClientCategoryBrowser,
			wantName:     "Chrome",
			wantVersion:  "120.0.0.0",
			wantOS:       "macos",
		},
		{
			name:         "chrome on windows",
			ua:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantCategory: ClientCategoryBrowser,
			wantName:     "Chrome",
			wantVersion:  "120.0.0.0",
			wantOS:       "windows",
		},
		{
			name:         "safari on macOS",
			ua:           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15",
			wantCategory: ClientCategoryBrowser,
			wantName:     "Safari",
			wantVersion:  "26.2",
			wantOS:       "macos",
		},
		{
			name:         "claude-code agent",
			ua:           "claude-code/2.1.202 (cli)",
			wantCategory: ClientCategoryAgent,
			wantName:     "claude-code",
			wantVersion:  "2.1.202",
		},
		{
			name:         "aws-mcp service ua",
			ua:           "aws-mcp.amazonaws.com",
			wantCategory: ClientCategoryAgent,
			wantName:     "aws-mcp",
		},
		{
			name:         "bun runtime agent",
			ua:           "Bun/1.4.0",
			wantCategory: ClientCategoryAgent,
			wantName:     "bun",
			wantVersion:  "1.4.0",
		},
		{
			name:         "unknown custom app",
			ua:           "CustomApp/1.0",
			wantCategory: ClientCategoryUnknown,
			wantName:     "CustomApp",
			wantVersion:  "1.0",
		},
		{
			name:         "empty ua",
			ua:           "",
			wantCategory: ClientCategoryUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseUserAgent(tt.ua)
			if got.Category != tt.wantCategory {
				t.Errorf("Category = %q, want %q", got.Category, tt.wantCategory)
			}
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if got.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", got.Version, tt.wantVersion)
			}
			if got.OS != tt.wantOS {
				t.Errorf("OS = %q, want %q", got.OS, tt.wantOS)
			}
			if got.OSVersion != tt.wantOSVer {
				t.Errorf("OSVersion = %q, want %q", got.OSVersion, tt.wantOSVer)
			}
			if got.Arch != tt.wantArch {
				t.Errorf("Arch = %q, want %q", got.Arch, tt.wantArch)
			}
			if got.Runtime != tt.wantRuntime {
				t.Errorf("Runtime = %q, want %q", got.Runtime, tt.wantRuntime)
			}
			if got.Command != tt.wantCommand {
				t.Errorf("Command = %q, want %q", got.Command, tt.wantCommand)
			}
			for k, want := range tt.wantComp {
				if got.Components[k] != want {
					t.Errorf("Components[%q] = %q, want %q", k, got.Components[k], want)
				}
			}
		})
	}
}

// TestParseUserAgentKey verifies the aggregation key distinguishes version and
// platform (Name + major identity) while collapsing command/component churn.
func TestParseUserAgentKey(t *testing.T) {
	base := "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 source/arm64 prompt/off command/s3.cp"
	other := "aws-cli/2.15.0 Python/3.11.6 Darwin/23.0.0 source/arm64 prompt/off command/s3.rb"
	diffVer := "aws-cli/2.16.0 Python/3.11.6 Darwin/23.0.0 source/arm64 prompt/off command/s3.cp"

	kBase := ParseUserAgent(base).Key()
	if got := ParseUserAgent(other).Key(); got != kBase {
		t.Errorf("different command should share key: %q vs %q", got, kBase)
	}
	if got := ParseUserAgent(diffVer).Key(); got == kBase {
		t.Errorf("different version should NOT share key, both were %q", got)
	}
}
