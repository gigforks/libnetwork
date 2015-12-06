package ovs

import (
	"fmt"
	"testing"

	"github.com/docker/libnetwork"
	"github.com/docker/libnetwork/config"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/options"
	"github.com/docker/libnetwork/types"
)

func TestDriverLoads(t *testing.T) {

	// Select and configure the network driver
	networkType := "ovs"

	// Create a new controller instance
	driverOptions := options.Generic{}
	genericOption := make(map[string]interface{})
	genericOption[netlabel.GenericData] = driverOptions
	controller, err := libnetwork.New(config.OptionDriverConfig(networkType, genericOption))
	if err != nil {
		return
	}

	// Create a network for containers to join.
	// NewNetwork accepts Variadic optional arguments that libnetwork and Drivers can use.
	network, err := controller.NewNetwork(networkType, "network1")
	if err != nil {
		return
	}

	// For each new container: allocate IP and  interfaces. The returned network
	// settings will be used for container infos (inspect and such), as well as
	// iptables rules for port publishing. This info is contained or accessible
	// from the returned endpoint.
	ep, err := network.CreateEndpoint("Endpoint1")
	if err != nil {
		return
	}

	// Create the sandbox for the container.
	// NewSandbox accepts Variadic optional arguments which libnetwork can use.
	sbx, err := controller.NewSandbox("container1",
		libnetwork.OptionHostname("test"),
		libnetwork.OptionDomainname("docker.io"))

	// A sandbox can join the endpoint via the join api.
	err = ep.Join(sbx)
	if err != nil {
		return
	}

	// libnetwork client can check the endpoint's operational data via the Info() API
	epInfo, err := ep.DriverInfo()
	mapData, ok := epInfo[netlabel.PortMap]
	if ok {
		portMapping, ok := mapData.([]types.PortBinding)
		if ok {
			fmt.Printf("Current port mapping for endpoint %s: %v", ep.Name(), portMapping)
		}
	}
}
