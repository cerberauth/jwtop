package main

import "github.com/cerberauth/jwtop/cmd"

var version = "dev"

func main() {
	cmd.Execute(version)
}
