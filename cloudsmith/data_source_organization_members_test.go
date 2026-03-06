//nolint:testpackage
package cloudsmith

import (
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Test member list function

func TestAccOrganizationMembersList_basic(t *testing.T) {
	t.Parallel()

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckOrganizationMembersListConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.cloudsmith_list_org_members.test", "is_active", "true"),
					testAccOrganizationMembersListContains("data.cloudsmith_list_org_members.test", "bblizniak"),
				),
			},
		},
	})
}

func testAccOrganizationMembersListContains(resourceName string, member string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		resourceState, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		pc, err := testAccProviderConfigForChecks()
		if err != nil {
			return err
		}

		req := pc.APIClient.OrgsApi.OrgsMembersRead(pc.Auth, os.Getenv("CLOUDSMITH_NAMESPACE"), member)
		memberDetails, _, err := pc.APIClient.OrgsApi.OrgsMembersReadExecute(req)
		if err != nil {
			return err
		}

		memberCount, err := strconv.Atoi(resourceState.Primary.Attributes["members.#"])
		if err != nil {
			return err
		}

		for i := 0; i < memberCount; i++ {
			prefix := fmt.Sprintf("members.%d.", i)
			if resourceState.Primary.Attributes[prefix+"user"] != member {
				continue
			}
			if resourceState.Primary.Attributes[prefix+"is_active"] != strconv.FormatBool(memberDetails.GetIsActive()) {
				return fmt.Errorf("member %s is_active mismatch", member)
			}
			if resourceState.Primary.Attributes[prefix+"has_two_factor"] != strconv.FormatBool(memberDetails.GetHasTwoFactor()) {
				return fmt.Errorf("member %s has_two_factor mismatch", member)
			}
			if resourceState.Primary.Attributes[prefix+"role"] != memberDetails.GetRole() {
				return fmt.Errorf("member %s role mismatch", member)
			}
			return nil
		}

		return fmt.Errorf("member %s not found in %s", member, resourceName)
	}
}

func testAccCheckOrganizationMembersListConfig() string {
	return fmt.Sprintf(`
data "cloudsmith_list_org_members" "test" {
    namespace = "%s"
    is_active = true
}
`, os.Getenv("CLOUDSMITH_NAMESPACE"))
}
