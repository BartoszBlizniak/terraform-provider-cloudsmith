package cloudsmith

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

var testAccManageTeamName = testAccUniqueName("acc-team-mgmt")

// create basic manage team test function

func TestAccManageTeam_basic(t *testing.T) {
	t.Parallel()
	resource.Test(t, resource.TestCase{
		PreCheck:          func() { testAccPreCheck(t) },
		ProviderFactories: testAccProviderFactories,
		CheckDestroy:      testAccTeamCheckDestroy("cloudsmith_team.test"),
		Steps: []resource.TestStep{
			{
				Config: testAccManageTeamConfigBasic,
				Check: resource.ComposeTestCheckFunc(
					testAccTeamCheckExists("cloudsmith_team.test"),
					resource.TestCheckResourceAttr("cloudsmith_manage_team.test", "members.0.role", "Member"),
					resource.TestCheckResourceAttr("cloudsmith_manage_team.test", "members.0.user", "bblizniak"),
				),
			},
		},
	})
}

var testAccManageTeamConfigBasic = fmt.Sprintf(`
resource "cloudsmith_team" "test" {
	organization = "%s"
	name = "%s"
}

resource "cloudsmith_manage_team" "test" {
	depends_on = [cloudsmith_team.test]
	organization = cloudsmith_team.test.organization
	team_name = cloudsmith_team.test.name
	members {
		role = "Member"
		user = "bblizniak"
	}
}
`, os.Getenv("CLOUDSMITH_NAMESPACE"), testAccManageTeamName)
