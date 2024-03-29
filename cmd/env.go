package cmd

import (
	"fmt"
	"github.com/99designs/keyring"
	"github.com/alessio/shellescape"
	"github.com/deamwork/aws-aad/lib"
	"github.com/spf13/cobra"
	"os"
	"strings"
	"time"
)

// envCmd represents the env command
var envCmd = &cobra.Command{
	Use:       "env <profile>",
	Short:     "env prints out export commands for the specified profile",
	RunE:      envRun,
	Example:   "source <(aws-okta env test)",
	ValidArgs: listProfileNames(mustListProfiles()),
}

func init() {
	RootCmd.AddCommand(envCmd)
	envCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for okta role session")
	envCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
}

func envRun(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return ErrTooFewArguments
	}

	profile := args[0]
	config, err := lib.NewConfigFromEnv()
	if err != nil {
		return err
	}

	profiles, err := config.Parse()
	if err != nil {
		return err
	}

	if _, ok := profiles[profile]; !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config. Use list command to see configured profiles", profile)
	}

	// check profile for both session durations if not explicitly set
	if !cmd.Flags().Lookup("assume-role-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, "assume_role_ttl", &assumeRoleTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse assume_role_ttl from profile config")
		}
	}

	if !cmd.Flags().Lookup("session-ttl").Changed {
		if err := updateDurationFromConfigProfile(profiles, profile, "session_ttl", &sessionTTL); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not parse session_ttl from profile config")
		}
	}

	opts := lib.ProviderOptions{
		Profiles:           profiles,
		SessionDuration:    sessionTTL,
		AssumeRoleDuration: assumeRoleTTL,
	}

	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}

	kr, err := lib.OpenKeyring(allowedBackends)
	if err != nil {
		return err
	}

	opts.SessionCacheSingleItem = flagSessionCacheSingleItem

	p, err := lib.NewProvider(kr, profile, opts)
	if err != nil {
		return err
	}

	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	roleARN, err := p.GetRoleARNWithRegion(creds)
	if err != nil {
		return err
	}
	role := strings.Split(roleARN, "/")[1]

	fmt.Printf("export AWS_ACCESS_KEY_ID=%s\n", shellescape.Quote(creds.AccessKeyID))
	fmt.Printf("export AWS_SECRET_ACCESS_KEY=%s\n", shellescape.Quote(creds.SecretAccessKey))
	fmt.Printf("export AWS_AAD_PROFILE=%s\n", shellescape.Quote(profile))
	fmt.Printf("export AWS_AAD_ASSUMED_ROLE_ARN=%s\n", shellescape.Quote(roleARN))
	fmt.Printf("export AWS_AAD_ASSUMED_ROLE=%s\n", shellescape.Quote(role))

	if region, ok := profiles[profile]["region"]; ok {
		fmt.Printf("export AWS_DEFAULT_REGION=%s\n", shellescape.Quote(region))
		fmt.Printf("export AWS_REGION=%s\n", shellescape.Quote(region))
	}

	if creds.SessionToken != "" {
		fmt.Printf("export AWS_SESSION_TOKEN=%s\n", shellescape.Quote(creds.SessionToken))
		fmt.Printf("export AWS_SECURITY_TOKEN=%s\n", shellescape.Quote(creds.SessionToken))
	}

	fmt.Printf("export AWS_AAD_SESSION_EXPIRATION=%d\n", p.GetExpiration().Unix())

	return nil
}
