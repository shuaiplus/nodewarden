// Exercise the same SDK calls as bitwarden/sm-kubernetes; input contains only local fixtures.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	sdk "github.com/bitwarden/sdk-go/v2"
)

func main() {
	var input struct {
		Origin, Token, OrganizationID, StateFile string
		LastSyncedDate                           *time.Time
	}
	check(json.NewDecoder(os.Stdin).Decode(&input))
	apiURL, identityURL := input.Origin+"/api", input.Origin+"/identity"
	client, err := sdk.NewBitwardenClient(&apiURL, &identityURL)
	check(err)
	defer client.Close()
	check(client.AccessTokenLogin(input.Token, &input.StateFile))
	result, err := client.Secrets().Sync(input.OrganizationID, input.LastSyncedDate)
	check(err)
	check(json.NewEncoder(os.Stdout).Encode(result))
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
