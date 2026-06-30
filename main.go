package main

import "github.com/cerberauth/jwtop/cmd"

var (
	version  = "dev"
	commit   = "none"
	date     = "unknown"
	clientID = "jwtop"
)

func main() {
	cmd.Execute(version, commit, date, clientID)
}
