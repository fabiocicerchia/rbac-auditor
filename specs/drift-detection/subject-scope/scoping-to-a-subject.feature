@domain:drift-detection @area:subject-scope @from:rbac-auditor/rbac-audit
Feature: Scoping an audit to one subject
  Lets a reviewer ask what changed for one user, group or ServiceAccount, without losing the gate on that subject's new access.

  Background:
    Giventhe committed snapshot before.json and a newer snapshot after.json

  @id:drift-detection.subject-scope.001 @rule:drift.subject.only-reaching-objects @verified @source:rbac_audit.py#subject_scope @test:tests/test_subject.py#test_only_objects_that_reach_the_subject_survive @test:tests/test_cli.py#test_the_matrix_replaces_the_object_diff
  Scenario: A subject-scoped diff mentions only the bindings that name the subject and the roles they reference
    Given ServiceAccount ci/deployer is newly bound to cluster-admin and its Role ci/deploy changed
    And Group system:unauthenticated was added to ClusterRoleBinding view-everyone
    When the operator runs `rbac-audit diff before.json after.json --subject ServiceAccount/ci/deployer`
    Then the report is headed Subject: ServiceAccount ci/deployer
    And a resource × verb matrix replaces the object diff, with rows such as deployments.apps
    And changes to ClusterRoleBinding/ci-admin and Role/ci/deploy are judged
    And ClusterRoleBinding/view-everyone is left out

  @id:drift-detection.subject-scope.002 @rule:drift.subject.scoped-diff-still-gates @verified @source:rbac_audit.py#report_and_exit @test:tests/test_subject.py#test_the_policy_still_gates_a_scoped_diff @test:tests/test_cli.py#test_the_subject_matrix_is_in_the_machine_output
  Scenario: A subject-scoped diff still fails on that subject's dangerous new access
    Given ServiceAccount ci/deployer is newly bound to cluster-admin
    When the operator runs `rbac-audit diff before.json after.json --subject ServiceAccount/ci/deployer`
    Then a cluster-admin-binding violation is reported
    And the command exits 2

  @id:drift-detection.subject-scope.003 @rule:drift.subject.unnamed-subject-has-no-permissions @verified @source:rbac_audit.py#render_matrix @test:tests/test_cli.py#test_an_untouched_subject_exits_0 @test:tests/test_subject.py#test_a_subject_nothing_names_has_an_empty_diff
  Scenario: A subject no binding names has an empty, passing diff
    Given no binding in either snapshot names User nobody
    When the operator runs `rbac-audit diff before.json after.json --subject User/nobody`
    Then the report says The subject has no permissions in either snapshot.
    And the command exits 0

  @id:drift-detection.subject-scope.004 @rule:drift.subject.invalid-subject-refused @verified @source:rbac_audit.py#parse_subject @test:tests/test_cli.py#test_a_malformed_subject_is_64_even_in_live_cluster_mode @test:tests/test_cli.py#test_a_namespace_on_a_group_is_a_usage_error @test:tests/test_subject.py#test_a_service_account_without_a_namespace_is_a_usage_error @test:tests/test_subject.py#test_an_unknown_kind_is_a_usage_error
  Scenario Outline: A subject that cannot match anything is refused as a usage error
    Given no NEW snapshot is given, so the live cluster would be read
    When the operator runs `rbac-audit diff before.json --subject <subject>`
    Then the command exits 64 without reading the cluster
    And stderr says <reason>

    Examples:
      | subject                         | reason                                            |
      | Robot/ci/x                      | the kind must be one of Group/ServiceAccount/User |
      | ServiceAccount/deployer         | a ServiceAccount needs its namespace              |
      | Group/ci/system:unauthenticated | a Group subject has no namespace                  |
      | User/a/b/c                      | --subject wants Kind/name or Kind/namespace/name  |
