package main

import (
	"flag"

	"github.com/cloudsmith-io/terraform-provider-cloudsmith/cloudsmith"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

// version is set by the release build via -ldflags "-X main.version=...".
// It ends up in the provider's User-Agent so Cloudsmith can tell which
// provider release a request came from.
var version = "dev"

func main() {
	var debugMode bool

	flag.BoolVar(&debugMode, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider { return cloudsmith.Provider(version) },
		ProviderAddr: "registry.terraform.io/cloudsmith-io/cloudsmith",
		Debug:        debugMode,
	})
}
