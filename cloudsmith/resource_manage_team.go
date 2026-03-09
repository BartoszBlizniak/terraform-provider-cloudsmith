package cloudsmith

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/cloudsmith-io/cloudsmith-api-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// The purpose of this resource is to add/remove users from a team in Cloudsmith

func importManageTeam(ctx context.Context, d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	idParts := strings.Split(d.Id(), ".")
	if len(idParts) != 2 {
		return nil, fmt.Errorf(
			"invalid import ID, must be of the form <organization_slug>.<team_slug>, got: %s", d.Id(),
		)
	}

	d.Set("organization", idParts[0])
	d.Set("team_name", idParts[1])
	return []*schema.ResourceData{d}, nil
}

func resourceManageTeamAdd(d *schema.ResourceData, m interface{}) error {
	return resourceManageTeamReplace(d, m, expandManageTeamMembers(d))
}

func expandManageTeamMembers(d *schema.ResourceData) []cloudsmith.OrganizationTeamMembership {
	teamMembersSet := d.Get("members").(*schema.Set).List()
	teamMembersList := make([]cloudsmith.OrganizationTeamMembership, len(teamMembersSet))

	for i, v := range teamMembersSet {
		teamMember := v.(map[string]interface{})
		teamMembersList[i] = cloudsmith.OrganizationTeamMembership{
			Role: teamMember["role"].(string),
			User: teamMember["user"].(string),
		}
	}

	return teamMembersList
}

func resourceManageTeamReplace(d *schema.ResourceData, m interface{}, members []cloudsmith.OrganizationTeamMembership) error {
	pc := m.(*providerConfig)
	organization := requiredString(d, "organization")
	teamName := requiredString(d, "team_name")

	teamMembersData := cloudsmith.OrganizationTeamMembers{
		Members: members,
	}

	req := pc.APIClient.OrgsApi.OrgsTeamsMembersUpdate(pc.Auth, organization, teamName)
	req = req.Data(teamMembersData)

	_, resp, err := pc.APIClient.OrgsApi.OrgsTeamsMembersUpdateExecute(req)
	if err != nil {
		return formatManageTeamAPIError(resp, err)
	}

	d.SetId(fmt.Sprintf("%s.%s", organization, teamName))

	return resourceManageTeamRead(d, m)
}

// We're using the replace members endpoint here so we need to compare the existing members with the new members and adjust the delta
func resourceManageTeamUpdateRemove(d *schema.ResourceData, m interface{}) error {
	return resourceManageTeamReplace(d, m, expandManageTeamMembers(d))
}

func resourceManageTeamRead(d *schema.ResourceData, m interface{}) error {
	// This function will read the team
	pc := m.(*providerConfig)

	organization := requiredString(d, "organization")
	teamName := requiredString(d, "team_name")

	req := pc.APIClient.OrgsApi.OrgsTeamsMembersList(pc.Auth, organization, teamName)

	teamMembers, resp, err := pc.APIClient.OrgsApi.OrgsTeamsMembersListExecute(req)
	if err != nil {
		if is404(resp) {
			d.SetId("")
			return nil
		}
		return err
	}

	// Map the members correctly
	members := make([]map[string]interface{}, len(teamMembers.GetMembers()))
	for i, member := range teamMembers.GetMembers() {
		members[i] = map[string]interface{}{
			"role": member.Role,
			"user": member.User,
		}
	}

	sort.Slice(members, func(i, j int) bool {
		if members[i]["user"].(string) == members[j]["user"].(string) {
			return members[i]["role"].(string) < members[j]["role"].(string)
		}
		return members[i]["user"].(string) < members[j]["user"].(string)
	})

	// Setting the values into the resource data
	d.Set("organization", organization)
	d.Set("team_name", teamName)
	d.Set("members", members)

	// Set the ID to the organization and team name, no slug returned from the API
	d.SetId(fmt.Sprintf("%s.%s", organization, teamName))

	return nil
}

func resourceManageTeamDelete(d *schema.ResourceData, m interface{}) error {
	return resourceManageTeamReplace(d, m, []cloudsmith.OrganizationTeamMembership{})
}

func formatManageTeamAPIError(resp *http.Response, err error) error {
	if resp == nil || resp.Body == nil {
		return err
	}

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil || len(body) == 0 {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(body))

	var payload map[string]interface{}
	if json.Unmarshal(body, &payload) != nil {
		return err
	}

	detail, _ := payload["detail"].(string)
	if fields, ok := payload["fields"]; ok {
		if message := firstManageTeamValidationMessage(fields); message != "" {
			if detail != "" {
				return fmt.Errorf("%s: %s", detail, message)
			}
			return fmt.Errorf("%s", message)
		}
	}
	if detail != "" {
		return fmt.Errorf("%s", detail)
	}

	return err
}

func firstManageTeamValidationMessage(v interface{}) string {
	switch typed := v.(type) {
	case string:
		return typed
	case []interface{}:
		for _, elem := range typed {
			if message := firstManageTeamValidationMessage(elem); message != "" {
				return message
			}
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if message := firstManageTeamValidationMessage(typed[key]); message != "" {
				return message
			}
		}
	}

	return ""
}

func resourceManageTeam() *schema.Resource {
	return &schema.Resource{
		Create: resourceManageTeamAdd,
		Read:   resourceManageTeamRead,
		Update: resourceManageTeamUpdateRemove,
		Delete: resourceManageTeamDelete,
		Importer: &schema.ResourceImporter{
			StateContext: importManageTeam,
		},

		Schema: map[string]*schema.Schema{
			"organization": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"team_name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"members": {
				Type: schema.TypeSet,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"role": {
							Type:     schema.TypeString,
							Required: true,
						},
						"user": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
				Required: true,
			},
		},
	}
}
