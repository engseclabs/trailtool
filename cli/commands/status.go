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
)

func StatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Check that TrailTool is set up and working",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			ok := true

			// 1. Check AWS credentials
			cfg, err := config.LoadDefaultConfig(ctx)
			if err != nil {
				fmt.Println("AWS credentials: FAIL")
				fmt.Fprintf(os.Stderr, "  Could not load AWS config: %v\n", err)
				fmt.Fprintf(os.Stderr, "  Set AWS_PROFILE and AWS_REGION, then re-authenticate.\n")
				ok = false
			} else {
				stsClient := sts.NewFromConfig(cfg)
				identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
				if err != nil {
					fmt.Println("AWS credentials: FAIL")
					fmt.Fprintf(os.Stderr, "  %v\n", err)
					fmt.Fprintf(os.Stderr, "  Set AWS_PROFILE and AWS_REGION, then re-authenticate.\n")
					ok = false
				} else {
					fmt.Printf("AWS credentials: OK (account %s)\n", aws.ToString(identity.Account))
				}

				// 2. Check CloudFormation stack
				if err == nil {
					cfnClient := cloudformation.NewFromConfig(cfg)
					stackFound := false
					for _, name := range []string{"trailtool-ingestor", "trailtool", "sam-app"} {
						_, err := cfnClient.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
							StackName: aws.String(name),
						})
						if err == nil {
							fmt.Printf("Ingestor stack: OK (%s)\n", name)
							stackFound = true
							break
						}
					}
					if !stackFound {
						fmt.Println("Ingestor stack: NOT FOUND")
						fmt.Fprintf(os.Stderr, "  No 'trailtool-ingestor', 'trailtool', or 'sam-app' CloudFormation stack found.\n")
						fmt.Fprintf(os.Stderr, "  Deploy the ingestor first: https://github.com/engseclabs/trailtool\n")
						ok = false
					}
				}
			}

			// 3. Check DynamoDB connectivity (try listing people)
			s, err := store.NewStore(ctx)
			if err == nil {
				_, err = s.ListPeople(ctx, CustomerID)
				if err != nil {
					fmt.Println("Data access: FAIL")
					fmt.Fprintf(os.Stderr, "  Could not query DynamoDB: %v\n", err)
					ok = false
				} else {
					fmt.Println("Data access: OK")
				}
			} else {
				fmt.Println("Data access: FAIL")
				fmt.Fprintf(os.Stderr, "  Could not connect to the data store: %v\n", err)
				ok = false
			}

			if !ok {
				os.Exit(1)
			}
			return nil
		},
	}
}
