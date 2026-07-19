// Package main is the entrypoint for the kubesurge CLI binary.
//
// .NET analogy: this is the equivalent of Program.cs — it wires up the
// dependency injection / service collection and calls Run().
// In Go there is no DI framework; we pass dependencies explicitly.
package main

import (
	"github.com/kubesurge/kubesurge/cmd"
)

// version is populated at link time using -ldflags:
//
//	go build -ldflags "-X main.version=1.0.0"
//
// This is standard Go practice (and used by GoReleaser).
// If built without flags (e.g. go run main.go), it defaults to "dev".
var version = "dev"

func main() {
	// Set the version string in the cmd package so that the CLI flags
	// and default image tags use the compiled CLI version.
	cmd.SetVersion(version)

	// cmd.Execute() is the Cobra equivalent of WebApplication.Run() in ASP.NET Core.
	// It parses os.Args, routes to the correct subcommand, and handles error exit codes.
	cmd.Execute()
}
