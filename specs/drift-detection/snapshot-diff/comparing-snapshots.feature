@domain:drift-detection @area:snapshot-diff @from:rbac-auditor/rbac-audit
Feature: Comparing RBAC snapshots
  Shows reviewers exactly which roles and bindings were added, removed or changed between two snapshots, so RBAC drift becomes a readable pull request.

  Background:
    Giventhe committed snapshot before.json and a newer snapshot after.json

  @id:drift-detection.snapshot-diff.001 @rule:drift.diff.changes-marked-with-detail @verified @source:rbac_audit.py#render_changes @test:tests/test_diff.py#test_human_output_marks_each_kind_of_change @test:tests/test_diff.py#test_every_change_renders_a_detail_line @test:tests/test_diff.py#test_removal_is_reported @test:tests/test_diff.py#test_changed_role_reports_rules_both_ways @test:tests/test_diff.py#test_the_core_api_group_is_rendered_visibly
  Scenario: Each added, removed or changed object is marked and explained
    Given after.json adds ClusterRoleBinding ci-admin, changes Role ci/deploy and adds Group system:unauthenticated to ClusterRoleBinding view-everyone
    When the operator runs `rbac-audit diff before.json after.json`
    Then the report lists + ClusterRoleBinding/ci-admin
    And it lists ~ Role/ci/deploy with + rule and - rule lines such as + rule apiGroups=* resources=secrets verbs=get
    And it lists + Group system:unauthenticated under the changed binding
    And every listed object has at least one detail line beneath it
    And diffing the other way, `rbac-audit diff after.json before.json`, lists - ClusterRoleBinding/ci-admin

  @id:drift-detection.snapshot-diff.002 @rule:drift.diff.identical-reports-no-changes @verified @source:rbac_audit.py#render_report @test:tests/test_cli.py#test_no_changes_exits_0 @test:tests/test_diff.py#test_a_snapshot_does_not_differ_from_itself
  Scenario: Identical snapshots report no changes and pass
    Given after.json is identical to before.json
    When the operator runs `rbac-audit diff before.json after.json`
    Then the report says No changes.
    And it says No policy violations.
    And the command exits 0

  @id:drift-detection.snapshot-diff.003 @rule:drift.diff.roleref-rewrite-regrants @verified @source:rbac_audit.py#_binding_delta @test:tests/test_diff.py#test_a_rewritten_role_ref_newly_grants_the_existing_subjects @test:tests/test_diff.py#test_an_unmoved_role_ref_newly_grants_only_the_added_subjects
  Scenario: A binding recreated against a different role newly grants that role to all its subjects
    Given before.json binds Group system:authenticated to ClusterRole view through ClusterRoleBinding view-everyone
    And after.json has view-everyone, with the same subjects, pointing at ClusterRole cluster-admin
    When the operator runs `rbac-audit diff before.json after.json`
    Then the report lists ~ ClusterRoleBinding/view-everyone with roleRef ClusterRole/cluster-admin (was ClusterRole/view)
    And no subject is shown as added or removed
    And the existing subjects are judged as newly granted cluster-admin

  @id:drift-detection.snapshot-diff.004 @rule:drift.diff.aggregation-change-shown @verified @source:rbac_audit.py#_role_delta @test:tests/test_diff.py#test_an_aggregation_change_is_reported
  Scenario: A change to a ClusterRole's aggregation selectors is shown
    Given after.json gives ClusterRole view an aggregationRule it did not have
    When the operator runs `rbac-audit diff before.json after.json`
    Then the report lists ~ ClusterRole/view
    And beneath it, a + aggregationRule line shows the new selectors
