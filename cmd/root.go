package cmd

import (
	"errors"
	"fmt"
	"github.com/99designs/keyring"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	"os"
	"strconv"
)

// Errors returned from frontend commands
var (
	ErrCommandMissing              = errors.New("must specify command to run")
	ErrTooManyArguments            = errors.New("too many arguments")
	ErrTooFewArguments             = errors.New("too few arguments")
	ErrFailedToSetCredentials      = errors.New("Failed to set credentials in your keyring")
	ErrFailedToValidateCredentials = errors.New("Failed to validate credentials")
	ErrFailedToGatherInformation   = errors.New("Failed to gather informations")
)

// global flags
var (
	backend                    string
	debug                      bool
	version                    string
	username                   string
	flagSessionCacheSingleItem bool
)

const envSessionCacheSingleItem = "AWS_AAD_SESSION_CACHE_SINGLE_ITEM"

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:               "aws-okta",
	Short:             "aws-okta allows you to authenticate with AWS using your okta credentials",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRunE: prerunE,
	PersistentPostRun: postrun,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(vers string, writeKey string) {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		switch err {
		case ErrTooFewArguments, ErrTooManyArguments:
			RootCmd.Usage()
		}
		os.Exit(1)
	}
}

func prerunE(cmd *cobra.Command, args []string) error {
	// Load backend from env var if not set as a flag
	if !cmd.Flags().Lookup("backend").Changed {
		backendFromEnv, ok := os.LookupEnv("AWS_OKTA_BACKEND")
		if ok {
			backend = backendFromEnv
		}
	}

	if debug {
		log.SetLevel(log.DebugLevel)
	}

	if !cmd.Flags().Lookup("session-cache-single-item").Changed {
		val, ok := os.LookupEnv(envSessionCacheSingleItem)
		if ok {
			valb, err := strconv.ParseBool(val)
			if err != nil {
				return xerrors.Errorf("couldn't parse as bool: %s: %w", val, err)
			}
			flagSessionCacheSingleItem = valb
		}
	}

	return nil
}

func postrun(cmd *cobra.Command, args []string) {}

func init() {
	backendsAvailable := []string{}
	for _, backendType := range keyring.AvailableBackends() {
		backendsAvailable = append(backendsAvailable, string(backendType))
	}
	RootCmd.PersistentFlags().StringVarP(&backend, "backend", "b", "", fmt.Sprintf("Secret backend to use %s", backendsAvailable))
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	RootCmd.PersistentFlags().BoolVarP(&flagSessionCacheSingleItem, "session-cache-single-item", "", false, fmt.Sprintf("(alpha) Enable single-item session cache; aka %s", envSessionCacheSingleItem))
}
