@domain:policy @area:privileged-subjects @from:rbac-auditor/rbac-audit-policy
Feature: Flagging bindings to privileged or unauthenticated subjects
  Blocks a change that grants access to anonymous callers or to system:masters, the group that bypasses RBAC entirely.

  Background:
    Given the default policy is in effect

  @id:policy.privileged-subjects.001 @rule:policy.subjects.anonymous-binding-blocks @verified @source:rbac_audit_policy.py#check_anonymous_subject @test:tests/test_policy.py#test_system_anonymous_user @test:tests/test_policy.py#test_system_unauthenticated_group @test:tests/test_policy.py#test_an_authenticated_group_does_not_fire
  Scenario Outline: Binding an anonymous or unauthenticated subject blocks the build
    Given a change that adds a ClusterRoleBinding x binding <subject> to view
    When the operator audits the change
    Then the audit reports <outcome>

    Examples:
      | subject                      | outcome                              |
      | User system:anonymous        | a blocking anonymous-subject finding |
      | Group system:unauthenticated | a blocking anonymous-subject finding |
      | Group system:authenticated   | no findings                          |

  @id:policy.privileged-subjects.002 @rule:policy.subjects.masters-binding-blocks-separately @verified @source:rbac_audit_policy.py#check_masters_subject @test:tests/test_policy.py#test_a_new_binding_to_system_masters_fires @test:tests/test_policy.py#test_it_is_exempted_separately_from_anonymous_subject
  Scenario: Binding system:masters blocks under its own rule
    Given a change that adds a ClusterRoleBinding x binding Group system:masters and Group system:unauthenticated to view
    When the operator audits the change
    Then the audit reports a blocking masters-subject finding for subject "Group system:masters"
    And the audit reports an anonymous-subject finding for Group system:unauthenticated
    And disabling or exempting masters-subject leaves the anonymous-subject finding in place

  @id:policy.privileged-subjects.003 @rule:policy.subjects.already-bound-subject-not-reflagged @verified @source:rbac_audit_policy.py#_watched_subjects @test:tests/test_policy.py#test_narrowing_a_binding_to_system_masters_does_not_fire @test:tests/test_policy.py#test_narrowing_a_bindings_role_does_not_fire_anonymous_subject @questionable
  Scenario Outline: Re-pointing a binding at another role does not re-flag a subject it already named
    Given an existing ClusterRoleBinding b binding <subject> to edit
    When the operator audits a change that points b at view instead
    Then the audit reports no findings

    Examples:
      | subject                      |
      | Group system:masters         |
      | Group system:unauthenticated |
