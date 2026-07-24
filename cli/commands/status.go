package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/spf13/cobra"

	"github.com/engseclabs/trailtool/core/store"
	"github.com/engseclabs/trailtool/internal/render"
)

// emitStatus writes one status line to stdout followed immediately by its detail
// lines to stderr, so a check's label always precedes its own detail even when
// stdout and stderr both point at the terminal (§5, fixes today's interleaving).
func emitStatus(rctx render.Context, level render.StatusLevel, label string, detail ...string) {
	fmt.Fprintln(rctx.Out, rctx.Status(level, label))
	for _, d := range detail {
		fmt.Fprintln(rctx.Err, "  "+rctx.Style(render.Muted, d))
	}
}

func StatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check that TrailTool is set up and working",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			rctx := renderContext()
			ok := true

			// 1. Check AWS credentials
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				emitStatus(rctx, render.StatusFail, "AWS credentials: FAIL",
					fmt.Sprintf("Could not load AWS config: %v", err),
					"Set AWS_PROFILE and AWS_REGION, then re-authenticate.")
				ok = false
			} else {
				stsClient := sts.NewFromConfig(cfg)
				identity, idErr := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if idErr != nil {
					emitStatus(rctx, render.StatusFail, "AWS credentials: FAIL",
						fmt.Sprintf("%v", idErr),
						"Set AWS_PROFILE and AWS_REGION, then re-authenticate.")
					ok = false
				} else {
					emitStatus(rctx, render.StatusOK,
						fmt.Sprintf("AWS credentials: OK (account %s)", aws.ToString(identity.Account)))
				}

				// 2. Check CloudFormation stack
				if idErr == nil {
					cfnClient := cloudformation.NewFromConfig(cfg)
					stackFound := false
					for _, name := range []string{"trailtool-ingestor", "trailtool", "sam-app"} {
						_, descErr := cfnClient.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
							StackName: aws.String(name),
						})
						if descErr == nil {
							emitStatus(rctx, render.StatusOK, fmt.Sprintf("Ingestor stack: OK (%s)", name))
							stackFound = true
							break
						}
					}
					if !stackFound {
						emitStatus(rctx, render.StatusWarn, "Ingestor stack: NOT FOUND",
							"No 'trailtool-ingestor', 'trailtool', or 'sam-app' CloudFormation stack found.",
							"Deploy the ingestor first: https://github.com/engseclabs/trailtool")
						ok = false
					}
				}
			}

			// 3. Check DynamoDB connectivity (try listing people)
			s, err := store.NewStore(ctx)
			if err == nil {
				if _, listErr := s.ListPeople(ctx, CustomerID); listErr != nil {
					emitStatus(rctx, render.StatusFail, "Data access: FAIL",
						fmt.Sprintf("Could not query DynamoDB: %v", listErr))
					ok = false
				} else {
					emitStatus(rctx, render.StatusOK, "Data access: OK")
				}
			} else {
				emitStatus(rctx, render.StatusFail, "Data access: FAIL",
					fmt.Sprintf("Could not connect to the data store: %v", err))
				ok = false
			}

			if !ok {
				os.Exit(1)
			}
			return nil
		},
	}
}
