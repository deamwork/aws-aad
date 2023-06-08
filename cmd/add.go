package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/99designs/keyring"
	"github.com/deamwork/aws-aad/lib"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	organization              string
	aadTenant                 string
	aadRegion                 string
	aadAccountName            string
	aadMiddlewareClientID     string
	aadMiddlewareClientSecret string
	aadCLIClientID            string
)

// addCmd represents the add command
var addCmd = &cobra.Command{
	Use:   "add",
	Short: "add your okta credentials",
	RunE:  add,
}

func init() {
	RootCmd.AddCommand(addCmd)
	addCmd.Flags().StringVarP(&aadTenant, "tenant", "", "", "Azure Tenant ID")
	addCmd.Flags().StringVarP(&username, "username", "", "", "Office 365 username")
	addCmd.Flags().StringVarP(&aadAccountName, "account", "", "", "Office 365 account name")
}

func add(cmd *cobra.Command, args []string) error {
	var allowedBackends []keyring.BackendType
	if backend != "" {
		allowedBackends = append(allowedBackends, keyring.BackendType(backend))
	}
	kr, err := lib.OpenKeyring(allowedBackends)

	if err != nil {
		log.Fatal(err)
	}

	// Ask Okta organization details if not given in command line argument
	if aadTenant == "" {
		organization, err = lib.Prompt("Azure tenant ID", false)
		if err != nil {
			return err
		}

		aadRegion, err = lib.Prompt("Azure region ([global], cn)", false)
		if err != nil {
			return err
		}
		if aadRegion == "" {
			aadRegion = "global"
		}

		tld, err := lib.GetAADDomain(aadRegion)
		if err != nil {
			return err
		}
		defaultTenant := fmt.Sprintf("%s/%s", tld, organization)

		aadTenant, err = lib.Prompt("Will login via https://"+defaultTenant+", is that ok? (Enter/Ctrl-C)", false)
		if err != nil {
			return err
		}
		if aadTenant == "" {
			aadTenant = defaultTenant
		}

		aadCLIClientID, err = lib.Prompt("CLI client ID (UUID)", false)
		if err != nil {
			return err
		}
		if aadCLIClientID == "" {
			return ErrFailedToGatherInformation
		}

		aadMiddlewareClientID, err = lib.Prompt("Middleware Client ID (UUID)", false)
		if err != nil {
			return err
		}
		if aadMiddlewareClientID == "" {
			return ErrFailedToGatherInformation
		}

		aadMiddlewareClientSecret, err = lib.Prompt("Middleware client secret (secure-input)", true)
		if err != nil {
			return err
		}
		if aadMiddlewareClientSecret == "" {
			return ErrFailedToGatherInformation
		}
	}

	if username == "" {
		username, err = lib.Prompt("Office 365 username, should be an email address", false)
		if err != nil {
			return err
		}
	}

	if aadAccountName == "" {
		aadAccountName = "aad-creds"
	} else {
		aadAccountName = "aad-creds-" + aadAccountName
	}
	log.Debugf("Keyring key: %s", aadAccountName)

	// Ask for password from prompt
	password, err := lib.Prompt("Office 365 password (secure-input)", true)
	if err != nil {
		return err
	}

	creds := lib.AADCreds{
		Organization:           organization,
		Username:               username,
		Password:               password,
		Domain:                 aadTenant,
		MiddlewareClientID:     aadMiddlewareClientID,
		MiddlewareClientSecret: aadMiddlewareClientSecret,
		CLIClientID:            aadCLIClientID,
	}

	encoded, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	item := keyring.Item{
		Key:                         aadAccountName,
		Data:                        encoded,
		Label:                       "aad credentials",
		KeychainNotTrustApplication: false,
	}

	if err := kr.Set(item); err != nil {
		log.Debugf("Failed to add user to keyring: %s", err)
		return ErrFailedToSetCredentials
	}

	log.Infof("Added credentials for user %s", username)
	return nil
}
