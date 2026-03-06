package cloudsmith

import (
	"fmt"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

	"github.com/cloudsmith-io/cloudsmith-api-go"
)

func retrieveOrgMemberListPage(pc *providerConfig, organization string, isActive bool, pageSize int64, page int64) ([]cloudsmith.OrganizationMembership, int64, error) {
	req := pc.APIClient.OrgsApi.OrgsMembersList(pc.Auth, organization)
	req = req.Page(page)
	req = req.PageSize(pageSize)
	req = req.IsActive(isActive)

	membersPage, httpResponse, err := pc.APIClient.OrgsApi.OrgsMembersListExecute(req)
	if err != nil {
		return nil, 0, err
	}
	pageTotal, err := strconv.ParseInt(httpResponse.Header.Get("X-Pagination-Pagetotal"), 10, 64)
	if err != nil {
		return nil, 0, err
	}
	return membersPage, pageTotal, nil
}

func retrieveAllOrgMembers(pc *providerConfig, organization string, isActive bool) ([]cloudsmith.OrganizationMembership, error) {
	const pageSize int64 = 100
	var membersList []cloudsmith.OrganizationMembership

	// Fetch the first page to discover total page count.
	firstPage, totalPages, err := retrieveOrgMemberListPage(pc, organization, isActive, pageSize, 1)
	if err != nil {
		return nil, err
	}
	membersList = append(membersList, firstPage...)

	// Fetch remaining pages.
	for page := int64(2); page <= totalPages; page++ {
		membersPage, _, err := retrieveOrgMemberListPage(pc, organization, isActive, pageSize, page)
		if err != nil {
			return nil, err
		}
		membersList = append(membersList, membersPage...)
	}

	return membersList, nil
}

// dataSourceOrganizationMembersListRead reads the organization members from the API and filters them based on the provided query.
func dataSourceOrganizationMembersListRead(d *schema.ResourceData, m interface{}) error {
	pc := m.(*providerConfig)
	namespace := d.Get("namespace").(string)
	isActive := d.Get("is_active").(bool)

	// Retrieve all organization members
	members, err := retrieveAllOrgMembers(pc, namespace, isActive)
	if err != nil {
		return fmt.Errorf("error retrieving organization members: %s", err)
	}

	// Map the filtered members to the schema
	if err := d.Set("members", flattenOrganizationMembers(members)); err != nil {
		return fmt.Errorf("error setting members: %s", err)
	}

	d.SetId(strconv.FormatInt(time.Now().Unix(), 10))
	return nil
}

// formatTimeOrEmpty safely formats a time value, returning an empty string for zero values.
func formatTimeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// flattenOrganizationMembers maps organization members to a format suitable for the schema.
func flattenOrganizationMembers(members []cloudsmith.OrganizationMembership) []interface{} {
	var out []interface{}
	for _, member := range members {
		m := make(map[string]interface{})
		m["email"] = member.GetEmail()
		m["has_two_factor"] = member.GetHasTwoFactor()
		m["is_active"] = member.GetIsActive()
		m["joined_at"] = formatTimeOrEmpty(member.GetJoinedAt())
		m["last_login_at"] = formatTimeOrEmpty(member.GetLastLoginAt())
		m["last_login_method"] = member.GetLastLoginMethod()
		m["role"] = member.GetRole()
		m["user"] = member.GetUser()
		m["user_id"] = member.GetUserId()
		out = append(out, m)
	}
	return out
}

func dataSourceOrganizationMembersList() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceOrganizationMembersListRead,
		Schema: map[string]*schema.Schema{
			"namespace": {
				Type:     schema.TypeString,
				Required: true,
			},
			"is_active": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"members": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"email": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"has_two_factor": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"is_active": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"joined_at": {
							Type:     schema.TypeString, // Assuming time.Time should be represented as a string
							Computed: true,
						},
						"last_login_at": {
							Type:     schema.TypeString, // Assuming time.Time should be represented as a string
							Computed: true,
						},
						"last_login_method": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"role": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"user": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"user_id": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}
