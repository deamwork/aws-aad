package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/deamwork/aws-aad/lib"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:       "login <profile>",
	Short:     "login will authenticate you through aad and allow you to access your AWS environment through a browser",
	RunE:      loginRun,
	PreRun:    loginPre,
	ValidArgs: listProfileNames(mustListProfiles()),
}

// Stdout is the bool for -stdout
var Stdout bool

func init() {
	RootCmd.AddCommand(loginCmd)
	loginCmd.Flags().BoolVarP(&Stdout, "stdout", "s", false, "Print login URL to stdout instead of opening in default browser")
	loginCmd.Flags().DurationVarP(&sessionTTL, "session-ttl", "t", time.Hour, "Expiration time for aad role session")
	loginCmd.Flags().DurationVarP(&assumeRoleTTL, "assume-role-ttl", "a", time.Hour, "Expiration time for assumed role")
}

func loginPre(cmd *cobra.Command, args []string) {
	if err := loadDurationFlagFromEnv(cmd, "session-ttl", "AWS_SESSION_TTL", &sessionTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_SESSION_TTL")
	}

	if err := loadDurationFlagFromEnv(cmd, "assume-role-ttl", "AWS_ASSUME_ROLE_TTL", &assumeRoleTTL); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to parse duration from AWS_ASSUME_ROLE_TTL")
	}
}

func loginRun(cmd *cobra.Command, args []string) error {
	if len(args) < 1 {
		return ErrTooFewArguments
	}
	if len(args) > 1 {
		return ErrTooManyArguments
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

	prof, ok := profiles[profile]
	if !ok {
		return fmt.Errorf("Profile '%s' not found in your aws config", profile)
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

	if _, ok := prof["aws_saml_url"]; ok {
		return aadLogin(p)
	}
	return federatedLogin(p, profile, profiles)
}

func aadLogin(p *lib.Provider) error {
	loginURL, err := p.GetSAMLLoginURL()
	if err != nil {
		return err
	}

	if Stdout {
		fmt.Println(loginURL.String())
	} else if err := open.Run(loginURL.String()); err != nil {
		return err
	}

	return nil
}

func federatedLogin(p *lib.Provider, profile string, profiles lib.Profiles) error {
	creds, err := p.Retrieve()
	if err != nil {
		return err
	}

	jsonBytes, err := json.Marshal(map[string]string{
		"sessionId":    creds.AccessKeyID,
		"sessionKey":   creds.SecretAccessKey,
		"sessionToken": creds.SessionToken,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("GET", "https://signin.aws.amazon.com/federation", nil)
	if err != nil {
		return err
	}
	q := req.URL.Query()
	q.Add("Action", "getSigninToken")
	q.Add("Session", string(jsonBytes))

	req.URL.RawQuery = q.Encode()

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Call to getSigninToken failed with %v", resp.Status)
	}

	var respParsed map[string]string
	if err = json.Unmarshal([]byte(body), &respParsed); err != nil {
		return err
	}

	signinToken, ok := respParsed["SigninToken"]
	if !ok {
		return err
	}

	destination := "https://console.aws.amazon.com/"
	prof := profiles[profile]
	if region, ok := prof["region"]; ok {
		destination = fmt.Sprintf(
			"https://%s.console.aws.amazon.com/console/home?region=%s",
			region, region,
		)
	}

	loginURL := fmt.Sprintf(
		"https://signin.aws.amazon.com/federation?Action=login&Issuer=aws-aad&Destination=%s&SigninToken=%s",
		url.QueryEscape(destination),
		url.QueryEscape(signinToken),
	)

	if Stdout {
		fmt.Println(loginURL)
	} else if err = open.Run(loginURL); err != nil {
		return err
	}

	return nil
}
