@domain:reporting @area:access-matrix @from:rbac-auditor/rbac-audit
Feature: Subject access matrix
  Shows a reviewer, per namespace and resource, which verbs one subject gained, lost or kept, so the effect of an RBAC change on a person or workload reads at a glance.

  Background:
    GivenServiceAccount ci/deployer is bound to roles in before.json and after.json

  @id:reporting.access-matrix.001 @rule:reporting.matrix.marks-gained-lost-unchanged @verified @source:rbac_audit.py#render_matrix @test:tests/test_subject.py#test_a_kept_verb_is_unchanged @test:tests/test_subject.py#test_a_lost_verb_is_marked_removed @test:tests/test_subject.py#test_columns_are_the_sorted_union_of_both_sides @test:tests/test_subject.py#test_rendering_marks_every_state
  Scenario: The matrix marks each verb as gained, lost, unchanged or not granted
    Given deployer could get and list deployments.apps in ci, and after.json adds patch
    When the operator runs `rbac-audit diff before.json after.json --subject ServiceAccount/ci/deployer`
    Then verb columns are the sorted union of both sides' verbs
    And row ci deployments.apps shows = under get and list and + under patch
    And a verb lost would show -, a verb never granted shows .
    And a legend explains + gained, - lost, = unchanged, . not granted

  @id:reporting.access-matrix.002 @rule:reporting.matrix.cluster-wide-is-star @verified @source:rbac_audit.py#effective_cells @test:tests/test_subject.py#test_a_cluster_wide_binding_is_scoped_to_star
  Scenario: Access through a cluster-wide binding is shown for every namespace
    Given after.json binds deployer to cluster-admin through a ClusterRoleBinding
    When the operator runs `rbac-audit diff before.json after.json --subject ServiceAccount/ci/deployer`
    Then the matrix has a row with namespace * and resource *.*
    And that row shows + under verb *

  @id:reporting.access-matrix.003 @rule:reporting.matrix.missing-role-grants-nothing @verified @source:rbac_audit.py#effective_cells @test:tests/test_subject.py#test_a_binding_to_a_missing_role_grants_nothing
  Scenario: A binding to a role that does not exist adds no rows
    Given RoleBinding ci/b binds deployer to Role ghost, which no snapshot holds
    When the operator runs the subject-scoped diff for ServiceAccount/ci/deployer
    Then the matrix shows no row for that binding

  @id:reporting.access-matrix.004 @rule:reporting.matrix.row-labels @verified @source:rbac_audit.py#resource_labels @test:tests/test_subject.py#test_the_core_group_leaves_the_resource_bare @test:tests/test_subject.py#test_resource_names_narrow_the_row @test:tests/test_subject.py#test_non_resource_urls_are_rows_of_their_own
  Scenario Outline: Matrix rows name resources the way kubectl does
    Given deployer's role has a rule on <rule>
    When the operator runs the subject-scoped diff for ServiceAccount/ci/deployer
    Then the matrix shows row <row>

    Examples:
      | rule                                        | row                |
      | pods in the core group and in apps          | pods and pods.apps |
      | secrets limited to resourceNames db and api | secrets[api,db]    |
      | nonResourceURL /healthz                     | /healthz           |
