//nolint:testpackage
package cloudsmith

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var (
	testAccRepositoryPrivilegesRepositoryName = testAccUniqueName("terraform-acc-privs")
	testAccServicePrivsName                   = testAccUniqueName("acc-svc-privs")
	testAccTeamPrivsName1                     = testAccUniqueName("acc-team-privs1")
	testAccTeamPrivsName2                     = testAccUniqueName("acc-team-privs2")
)

// TestAccRepositoryPrivileges_basic spins up a repository with default options,
// creates a service account and a couple of teams, assigning and modifying
// their permissions before tearing down and verifying deletion.
func TestAccRepositoryPrivileges_basic(t *testing.T) {
	t.Parallel()

	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccRepositoryCheckDestroy("cloudsmith_repository.test"),
		Steps: []resource.TestStep{
			{
				Config: testAccRepositoryPrivilegesConfigBasic,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cloudsmith_repository_privileges.test", "service.0.privilege", "Read"),
				),
			},
			{
				Config: testAccRepositoryPrivilegesConfigBasicUpdatePrivilege,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cloudsmith_repository_privileges.test", "service.0.privilege", "Write"),
				),
			},
			{
				Config: testAccRepositoryPrivilegesConfigBasicAddTeam,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cloudsmith_repository_privileges.test", "service.0.privilege", "Write"),
					resource.TestCheckResourceAttr("cloudsmith_repository_privileges.test", "team.0.privilege", "Write"),
				),
			},
			{
				Config: testAccRepositoryPrivilegesConfigBasicAddAnotherTeam,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("cloudsmith_repository_privileges.test", "service.0.privilege", "Write"),
					resource.TestCheckTypeSetElemNestedAttrs("cloudsmith_repository_privileges.test", "team.*", map[string]string{
						"privilege": "Write",
						"slug":      "tf-test-team-privs-2",
					}),
					resource.TestCheckTypeSetElemNestedAttrs("cloudsmith_repository_privileges.test", "team.*", map[string]string{
						"privilege": "Read",
						"slug":      "tf-test-team-privs-1",
					}),
				),
			},
			{
				ResourceName: "cloudsmith_repository_privileges.test",
				ImportState:  true,
				ImportStateIdFunc: func(s *terraform.State) (string, error) {
					resourceState := s.RootModule().Resources["cloudsmith_repository_privileges.test"]
					return fmt.Sprintf(
						"%s.%s",
						resourceState.Primary.Attributes["organization"],
						resourceState.Primary.Attributes["repository"],
					), nil
				},
				ImportStateVerify: true,
			},
		},
	})
}

var testAccRepositoryPrivilegesConfigBasic = fmt.Sprintf(`
resource "cloudsmith_repository" "test" {
	name      = "%s"
	namespace = "%s"
}

resource "cloudsmith_service" "test" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
	role         = "Member"
}

data "cloudsmith_user_self" "current" {}

resource "cloudsmith_repository_privileges" "test" {
    organization = cloudsmith_repository.test.namespace
    repository   = cloudsmith_repository.test.slug

	service {
		privilege = "Read"
		slug      = cloudsmith_service.test.slug
	}

	# Include the authenticated account explicitly to satisfy lockout safeguard.
	user {
		privilege = "Admin"
		slug      = data.cloudsmith_user_self.current.slug
	}
}
`, testAccRepositoryPrivilegesRepositoryName, os.Getenv("CLOUDSMITH_NAMESPACE"), testAccServicePrivsName)

var testAccRepositoryPrivilegesConfigBasicUpdatePrivilege = fmt.Sprintf(`
resource "cloudsmith_repository" "test" {
	name      = "%s"
	namespace = "%s"
}

resource "cloudsmith_service" "test" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
	role         = "Member"
}

data "cloudsmith_user_self" "current" {}

resource "cloudsmith_repository_privileges" "test" {
    organization = cloudsmith_repository.test.namespace
    repository   = cloudsmith_repository.test.slug

	service {
		privilege = "Write"
		slug      = cloudsmith_service.test.slug
	}

	# Include the authenticated account explicitly to satisfy lockout safeguard.
	user {
		privilege = "Admin"
		slug      = data.cloudsmith_user_self.current.slug
	}
}
`, testAccRepositoryPrivilegesRepositoryName, os.Getenv("CLOUDSMITH_NAMESPACE"), testAccServicePrivsName)

var testAccRepositoryPrivilegesConfigBasicAddTeam = fmt.Sprintf(`
resource "cloudsmith_repository" "test" {
	name      = "%s"
	namespace = "%s"
}

resource "cloudsmith_service" "test" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
	role         = "Member"
}

resource "cloudsmith_team" "test_1" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
}

resource "cloudsmith_repository_privileges" "test" {
    organization = cloudsmith_repository.test.namespace
    repository   = cloudsmith_repository.test.slug

	service {
		privilege = "Write"
		slug      = cloudsmith_service.test.slug
	}

	team {
		privilege = "Write"
		slug      = cloudsmith_team.test_1.slug
	}
}
`, testAccRepositoryPrivilegesRepositoryName, os.Getenv("CLOUDSMITH_NAMESPACE"), testAccServicePrivsName, testAccTeamPrivsName1)

var testAccRepositoryPrivilegesConfigBasicAddAnotherTeam = fmt.Sprintf(`
resource "cloudsmith_repository" "test" {
	name      = "%s"
	namespace = "%s"
}

resource "cloudsmith_service" "test" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
	role         = "Member"
}

resource "cloudsmith_team" "test_1" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
}

resource "cloudsmith_team" "test_2" {
	name         = "%s"
	organization = cloudsmith_repository.test.namespace
}

resource "cloudsmith_repository_privileges" "test" {
    organization = cloudsmith_repository.test.namespace
    repository   = cloudsmith_repository.test.slug

	service {
		privilege = "Write"
		slug      = cloudsmith_service.test.slug
	}

	team {
		privilege = "Write"
		slug      = cloudsmith_team.test_2.slug
	}

	team {
		privilege = "Read"
		slug      = cloudsmith_team.test_1.slug
	}
}
`, testAccRepositoryPrivilegesRepositoryName, os.Getenv("CLOUDSMITH_NAMESPACE"), testAccServicePrivsName, testAccTeamPrivsName1, testAccTeamPrivsName2)
