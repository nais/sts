package oauth

import "slices"

type OAuthClient struct {
	ID                string
	WorkloadIssuer    string
	WorkloadSubject   string

	// TODO: should be one or the other, not both
	AllowedAudiences  []string
	AccessControlList AccessControlList
}

type AccessControlList struct {
	Allowed []AccessControlListEntry
}

type AccessControlListEntry struct {
	OAuthClient
	Roles []string
}

func (c *OAuthClient) allowsAudience(audience string) bool {
	return slices.Contains(c.AllowedAudiences, audience)
}
