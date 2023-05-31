package main

import (
	"aws-aad/cmd"
	"aws-aad/utils/metadata"
)

var (
	Version = "dev"
)

func main() {
	metadata.SetAppName("aws-aad")
	cmd.Start()
}
