package aad_test

import rego.v1

import data.aad

PimUser := "00000000-0000-0000-0000-000000000001"
PimGroup := "00000000-0000-0000-0000-000000000002"

PimRole(Assignments) := {"DisplayName": "Global Administrator", "Assignments": Assignments}

OutsidePimAssignment(Principal) := {"PrincipalId": Principal, "StartDateTime": null}

PimExclusionConfig(Users, Groups) := {"Aad": {"MS.AAD.7.5v1": {"RoleExclusions": {"Users": Users, "Groups": Groups}}}}

PimPolicyResult(Roles, Config) := Result if {
	Results := aad.tests with input as {
		"privileged_roles": Roles,
		"service_plans": ServicePlans,
		"scuba_config": Config,
	}
	some Result in Results
	Result.PolicyId == "MS.AAD.7.5v1"
}

test_PimRoleExclusions_User if {
	Result := PimPolicyResult([PimRole([OutsidePimAssignment(PimUser)])], PimExclusionConfig([PimUser], []))
	Result.RequirementMet
	Result.ActualValue == set()
}

test_PimRoleExclusions_Group if {
	Result := PimPolicyResult([PimRole([OutsidePimAssignment(PimGroup)])], PimExclusionConfig([], [PimGroup]))
	Result.RequirementMet
	Result.ActualValue == set()
}

test_PimRoleExclusions_UsersAndGroups if {
	Role := PimRole([OutsidePimAssignment(PimUser), OutsidePimAssignment(PimGroup)])
	Result := PimPolicyResult([Role], PimExclusionConfig([PimUser], [PimGroup]))
	Result.RequirementMet
	Result.ActualValue == set()
}

test_PimRoleExclusions_Partial if {
	Role := PimRole([OutsidePimAssignment(PimUser), OutsidePimAssignment(PimGroup)])
	Result := PimPolicyResult([Role], PimExclusionConfig([PimUser], []))
	not Result.RequirementMet
	Result.ActualValue == {"Global Administrator"}
}

test_PimRoleExclusions_EmptyOrMissing if {
	every Config in [{}, {"Aad": {}}, {"Aad": {"MS.AAD.7.5v1": {}}}, PimExclusionConfig([], []), PimExclusionConfig(null, null)] {
		Result := PimPolicyResult([PimRole([OutsidePimAssignment(PimUser)])], Config)
		not Result.RequirementMet
		Result.ActualValue == {"Global Administrator"}
	}
}

test_PimRoleExclusions_MissingUsers if {
	Config := {"Aad": {"MS.AAD.7.5v1": {"RoleExclusions": {"Groups": [PimGroup]}}}}
	Result := PimPolicyResult([PimRole([OutsidePimAssignment(PimGroup)])], Config)
	Result.RequirementMet
}

test_PimRoleExclusions_MissingGroups if {
	Config := {"Aad": {"MS.AAD.7.5v1": {"RoleExclusions": {"Users": [PimUser]}}}}
	Result := PimPolicyResult([PimRole([OutsidePimAssignment(PimUser)])], Config)
	Result.RequirementMet
}

test_PimRoleExclusions_UnidentifiedPrincipals if {
	every Assignment in [{"StartDateTime": null}, OutsidePimAssignment(null), OutsidePimAssignment("")] {
		Result := PimPolicyResult([PimRole([Assignment])], PimExclusionConfig([null, ""], [null, ""]))
		not Result.RequirementMet
		Result.ActualValue == {"Global Administrator"}
	}
}

test_PimRoleExclusions_DoesNotUseOtherPolicy if {
	Config := {"Aad": {"MS.AAD.7.4v1": {"RoleExclusions": {"Users": [PimUser]}}}}
	Result := PimPolicyResult([PimRole([OutsidePimAssignment(PimUser)])], Config)
	not Result.RequirementMet
	Result.ActualValue == {"Global Administrator"}
}

test_PimRoleExclusions_PimAssignmentsStillPass if {
	Role := PimRole([{"PrincipalId": PimUser, "StartDateTime": "2026-09-09T00:00:00Z"}])
	Result := PimPolicyResult([Role], {})
	Result.RequirementMet
	Result.ActualValue == set()
}

test_PimRoleExclusions_OtherRolesStillFail if {
	Roles := [
		PimRole([OutsidePimAssignment(PimUser)]),
		{"DisplayName": "Application Administrator", "Assignments": [OutsidePimAssignment(PimGroup)]},
	]
	Result := PimPolicyResult(Roles, PimExclusionConfig([PimUser], []))
	not Result.RequirementMet
	Result.ActualValue == {"Application Administrator"}
}

test_PimRoleExclusions_P2LicenseStillRequired if {
	Results := aad.tests with input as {
		"privileged_roles": [PimRole([OutsidePimAssignment(PimUser)])],
		"service_plans": [],
		"scuba_config": PimExclusionConfig([PimUser], []),
	}
	some Result in Results
	Result.PolicyId == "MS.AAD.7.5v1"
	not Result.RequirementMet
	Result.ActualValue == set()
}
