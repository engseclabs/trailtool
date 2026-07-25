package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/store"
	"github.com/engseclabs/trailtool/internal/render"
)

// StatusCheck is one stable machine-readable setup check.
type StatusCheck struct {
	Check       string   `json:"check"`
	Status      string   `json:"status"`
	Message     string   `json:"message"`
	Diagnostics []string `json:"diagnostics"`
}

type statusChecker func(context.Context) []StatusCheck
type statusExit func(int)

// emitStatus writes one status line to stdout followed immediately by its detail
// lines to stderr, so each check precedes its diagnostics.
func emitStatus(rctx render.Context, level render.StatusLevel, label string, detail ...string) {
	fmt.Fprintln(rctx.Out, rctx.Status(level, label))
	for _, d := range detail {
		fmt.Fprintln(rctx.Err, "  "+rctx.Style(render.Muted, d))
	}
}

func StatusCmd() *cobra.Command {
	return statusCmd(collectStatusChecks, os.Exit)
}

func statusCmd(check statusChecker, exit statusExit) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check that TrailTool is set up and working",
		RunE: func(cmd *cobra.Command, args []string) error {
			checks := check(cmd.Context())
			if err := writeStatusChecks(cmd, checks); err != nil {
				return err
			}
			if !statusHealthy(checks) {
				exit(1)
			}
			return nil
		},
	}
}

func collectStatusChecks(ctx context.Context) []StatusCheck {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return []StatusCheck{
			newStatusCheck("aws_credentials", "fail", "Could not load AWS configuration",
				err.Error(), "Set AWS_PROFILE and AWS_REGION, then re-authenticate."),
			newStatusCheck("ingestor_stack", "skipped", "AWS configuration is unavailable"),
			newStatusCheck("data_access", "skipped", "AWS configuration is unavailable"),
		}
	}

	checks := make([]StatusCheck, 0, 3)
	stsClient := sts.NewFromConfig(cfg)
	identity, identityErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if identityErr != nil {
		checks = append(checks,
			newStatusCheck("aws_credentials", "fail", "Could not authenticate to AWS",
				identityErr.Error(), "Set AWS_PROFILE and AWS_REGION, then re-authenticate."),
			newStatusCheck("ingestor_stack", "skipped", "AWS credentials could not be verified"),
		)
	} else {
		checks = append(checks, newStatusCheck(
			"aws_credentials", "ok", "Authenticated to account "+aws.ToString(identity.Account),
		))

		cfnClient := cloudformation.NewFromConfig(cfg)
		stackName := ""
		for _, name := range []string{"trailtool-ingestor", "trailtool", "sam-app"} {
			if _, stackErr := cfnClient.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
				StackName: aws.String(name),
			}); stackErr == nil {
				stackName = name
				break
			}
		}
		if stackName == "" {
			checks = append(checks, newStatusCheck(
				"ingestor_stack",
				"warn",
				"No TrailTool CloudFormation stack was found",
				"Checked trailtool-ingestor, trailtool, and sam-app.",
				"Deploy the ingestor: https://github.com/engseclabs/trailtool",
			))
		} else {
			checks = append(checks, newStatusCheck(
				"ingestor_stack", "ok", "Found CloudFormation stack "+stackName,
			))
		}
	}

	s := store.NewStoreFromConfig(cfg)
	if _, dataErr := s.ListPeople(ctx, CustomerID); dataErr != nil {
		checks = append(checks, newStatusCheck(
			"data_access", "fail", "Could not query TrailTool data", dataErr.Error(),
		))
	} else {
		checks = append(checks, newStatusCheck("data_access", "ok", "TrailTool data is accessible"))
	}
	return checks
}

func newStatusCheck(check, status, message string, diagnostics ...string) StatusCheck {
	if diagnostics == nil {
		diagnostics = []string{}
	}
	return StatusCheck{
		Check:       check,
		Status:      status,
		Message:     message,
		Diagnostics: diagnostics,
	}
}

func writeStatusChecks(cmd *cobra.Command, checks []StatusCheck) error {
	if Format == "json" {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(checks)
	}

	rctx := renderContext()
	rctx.Out = cmd.OutOrStdout()
	rctx.Err = cmd.ErrOrStderr()
	for _, check := range checks {
		details := check.Diagnostics
		if check.Status != "ok" && check.Message != "" {
			details = append([]string{check.Message}, details...)
		}
		emitStatus(rctx, statusLevel(check.Status), statusLabel(check), details...)
	}
	return nil
}

func statusHealthy(checks []StatusCheck) bool {
	for _, check := range checks {
		if check.Status != "ok" {
			return false
		}
	}
	return true
}

func statusLevel(status string) render.StatusLevel {
	switch status {
	case "ok":
		return render.StatusOK
	case "warn", "skipped":
		return render.StatusWarn
	default:
		return render.StatusFail
	}
}

func statusLabel(check StatusCheck) string {
	title := map[string]string{
		"aws_credentials": "AWS credentials",
		"ingestor_stack":  "Ingestor stack",
		"data_access":     "Data access",
	}[check.Check]
	if title == "" {
		title = check.Check
	}

	switch check.Status {
	case "ok":
		if check.Check == "aws_credentials" {
			return title + ": OK (account " + strings.TrimPrefix(check.Message, "Authenticated to account ") + ")"
		}
		if check.Check == "ingestor_stack" {
			return title + ": OK (" + strings.TrimPrefix(check.Message, "Found CloudFormation stack ") + ")"
		}
		return title + ": OK"
	case "warn":
		return title + ": NOT FOUND"
	case "skipped":
		return title + ": SKIPPED"
	default:
		return title + ": FAIL"
	}
}
