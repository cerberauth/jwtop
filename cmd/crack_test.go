package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCrackCmd_ExternalToolFlagsRegistered(t *testing.T) {
	for _, name := range []string{"john", "john-path", "hashcat", "hashcat-path", "crack-timeout"} {
		flag := crackCmd.Flags().Lookup(name)
		require.NotNilf(t, flag, "expected --%s to be registered on crackCmd", name)
	}

	johnFlag := crackCmd.Flags().Lookup("john")
	assert.Equal(t, "false", johnFlag.DefValue)
	hashcatFlag := crackCmd.Flags().Lookup("hashcat")
	assert.Equal(t, "false", hashcatFlag.DefValue)
	timeoutFlag := crackCmd.Flags().Lookup("crack-timeout")
	assert.Equal(t, (5 * time.Minute).String(), timeoutFlag.DefValue)
}
