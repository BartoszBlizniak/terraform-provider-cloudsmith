//nolint:testpackage
package cloudsmith

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// Test member list function

func TestAccOrganizationMembersList_basic(t *testing.T) {
	t.Parallel()

	resource.Test(t, resource.TestCase{
		PreCheck:  func() { testAccPreCheck(t) },
		Providers: testAccProviders,
		Steps: []resource.TestStep{
			{
				Config: testAccCheckOrganizationMembersListConfig(),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("data.cloudsmith_list_org_members.test", "is_active", "true"),
					testAccOrganizationMemberInList("data.cloudsmith_list_org_members.test", "bblizniak", map[string]string{
						"has_two_factor": "true",
						"is_active":      "true",
					}),
				),
			},
		},
	})
}

func testAccOrganizationMemberInList(resourceName, username string, attrs map[string]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource not found: %s", resourceName)
		}

		memberCount := rs.Primary.Attributes["members.#"]
		for i := 0; i < len(rs.Primary.Attributes); i++ {
			userKey := fmt.Sprintf("members.%d.user", i)
			if rs.Primary.Attributes[userKey] != username {
				continue
			}
			for attr, expected := range attrs {
				key := fmt.Sprintf("members.%d.%s", i, attr)
				if rs.Primary.Attributes[key] != expected {
					return fmt.Errorf("attribute %s expected %q, got %q", key, expected, rs.Primary.Attributes[key])
				}
			}
			return nil
		}

		return fmt.Errorf("member %q not found in %s (members.#=%s)", username, resourceName, memberCount)
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
