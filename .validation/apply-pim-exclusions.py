"""Apply the candidate patch in an isolated validation checkout."""
from pathlib import Path
import re
import textwrap

root = Path('PowerShell/ScubaGear')


def replace(path, old, new):
    source = path.read_text(encoding='utf-8')
    assert source.count(old) == 1, (str(path), old)
    path.write_text(source.replace(old, new), encoding='utf-8')


path = root / 'Rego/AADConfig.rego'
source = path.read_text()
replacement = '''RolesAssignedOutsidePim contains Role.DisplayName if {
    AllowedUsers := {User |
        some User in input.scuba_config.Aad["MS.AAD.7.5v1"].RoleExclusions.Users
        is_string(User)
        User != ""
    }
    AllowedGroups := {Group |
        some Group in input.scuba_config.Aad["MS.AAD.7.5v1"].RoleExclusions.Groups
        is_string(Group)
        Group != ""
    }
    some Role in input.privileged_roles
    some Assignment in Role.Assignments
    is_null(Assignment.StartDateTime)
    Principal := object.get(Assignment, "PrincipalId", null)
    not Principal in (AllowedUsers | AllowedGroups)
}'''
source, count = re.subn(r'RolesAssignedOutsidePim contains Role.DisplayName if \{\n.*?\n\}', replacement, source, flags=re.S)
assert count == 1
path.write_text(source)

path = root / 'Modules/ScubaConfig/ScubaConfigSchema.json'
source = path.read_text()
source, count = re.subn(r'("MS\.AAD\.7\.4v1":\s*\[\s*"RoleExclusions"\s*\],)', r'\1\n      "MS.AAD.7.5v1": ["RoleExclusions"],', source)
assert count == 1
path.write_text(source)

marker = '<!--Policy: MS.AAD.7.5v1; Criticality: SHALL -->'
replace(root / 'baselines/aad.md', marker, marker + '\n<!--ExclusionType: RoleExclusions-->')

path = root / 'schemas/ScubaBaselines.json'
source = path.read_text(encoding='utf-8')
source, count = re.subn(r'("id":\s*"MS\.AAD\.7\.5v1".*?"exclusionField":\s*)"none"', r'\1"RoleExclusions"', source, count=1, flags=re.S)
assert count == 1
path.write_text(source, encoding='utf-8')

path = root / 'Modules/Support/Support.psm1'
replace(path, '$RoleExclusionNamespace = "MS.AAD.7.4v1"', '$RoleExclusionNamespace = @("MS.AAD.7.4v1", "MS.AAD.7.5v1")')
replace(path, '    $AadTemplate.add($RoleExclusionNamespace, $AadRoleExclusions)', '    foreach ($Policy in $RoleExclusionNamespace) {\n        $AadTemplate.add($Policy, $AadRoleExclusions)\n    }')

path = root / 'Sample-Config-Files/full_config.yaml'
source = path.read_text()
position = source.index('# EXCLUSIONS : EXO SAMPLE')
separator = source.rfind('# ========================', 0, position)
assert separator > 0
source = source[:separator] + '  # Provisioning to highly privileged roles SHALL occur through a PAM system.\n  MS.AAD.7.5v1: *CommonRoleExclusions\n\n' + source[separator:]
path.write_text(source)

path = root / 'Sample-Config-Files/scuba_compliance.yaml'
source = path.read_text()
match = re.search(r'(  MS\.AAD\.7\.4v1:\n.*?)(?=\n\S)', source, flags=re.S)
assert match
block = match.group(1)
source = source[:match.end()] + '\n' + block.replace('MS.AAD.7.4v1', 'MS.AAD.7.5v1') + source[match.end():]
path.write_text(source)

replace(Path('docs/configuration/configuration.md'), '- MS.AAD.7.4v1\n',
        '- MS.AAD.7.4v1\n- MS.AAD.7.5v1\n\n'
        'For `MS.AAD.7.5v1`, use the same `RoleExclusions.Users` and\n'
        '`RoleExclusions.Groups` structure shown above, under the `MS.AAD.7.5v1`\n'
        'key. Exclusions are scoped to each policy and match the assigned user or\n'
        'group ID. An exclusion for one assignment does not exempt other\n'
        'assignments to the same role.\n')

path = root / 'Testing/Unit/PowerShell/Support/New-SCuBAConfig.Tests.ps1'
marker = '        Context "When policy IDs are provided in the OmitPolicy parameter" {'
test = textwrap.indent(textwrap.dedent('''\
It 'Includes user and group exclusions for both privileged-role policies' {
    $Captured = @{}
    Mock -ModuleName Support -CommandName ConvertTo-Yaml {
        $Captured.Config = $args[0]
        $args[0]
    }
    New-SCuBAConfig @CMDArgs
    Should -Invoke -CommandName ConvertTo-Yaml -Exactly -Times 1
    foreach ($PolicyId in @("MS.AAD.7.4v1", "MS.AAD.7.5v1")) {
        $Captured.Config["Aad"].Contains($PolicyId) | Should -BeTrue
        $Captured.Config["Aad"][$PolicyId].RoleExclusions.Users | Should -HaveCount 1
        $Captured.Config["Aad"][$PolicyId].RoleExclusions.Groups | Should -HaveCount 1
    }
}

'''), '        ')
replace(path, marker, test + marker)
