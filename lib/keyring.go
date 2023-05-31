package lib

import (
	"os"

	"github.com/99designs/keyring"
)

func keyringPrompt(prompt string) (string, error) {
	return PromptWithOutput(prompt, true, os.Stderr)
}

func OpenKeyring(allowedBackends []keyring.BackendType) (kr keyring.Keyring, err error) {
	kr, err = keyring.Open(keyring.Config{
		AllowedBackends:          allowedBackends,
		KeychainTrustApplication: true,
		// this keychain name is for backwards compatibility
		ServiceName:             "aws-aad-login",
		LibSecretCollectionName: "awsvault",
		FileDir:                 "~/.aws-aad/",
		FilePasswordFunc:        keyringPrompt,
	})

	return
}
