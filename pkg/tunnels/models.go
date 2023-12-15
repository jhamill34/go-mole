package tunnels

import "fmt"

type BastionEntity struct {
	Id   string `json:"id"`
	IP   string `json:"ip"`
	User string `json:"user"`
}

type EndpointInfo struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
}

func (e *EndpointInfo) String() string {
	if e.Protocol == "tcp" {
		return fmt.Sprintf(
			"%s:%d",
			e.Host,
			e.Port,
		)
	}

	return fmt.Sprintf("%s://%s:%d", e.Protocol, e.Host, e.Port)
}
