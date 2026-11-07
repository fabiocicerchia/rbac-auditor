@domain:policy @area:gating @from:rbac-auditor/rbac-audit
Feature: Gating a build on the policy
  Lets CI pass or fail a change on the policy verdict through a stable exit code, with a report-only mode for rolling the gate out.

  Background:
    Giventhe committed snapshot before.json and a newer snapshot after.json

  @id:policy.gating.001 @rule:policy.gating.exit-code-reflects-verdict @verified @source:rbac_audit.py#report_and_exit @test:tests/test_cli.py#test_policy_violations_exit_2 @test:tests/test_cli.py#test_a_new_binding_to_system_masters_fails_the_gate @test:tests/test_cli.py#test_no_changes_exits_0 @test:tests/test_cli.py#test_warn_only_rules_report_but_do_not_gate
  Scenario Outline: The exit code is 2 when a gating violation is found and 0 otherwise
    Given after.json <change>
    When the operator runs `rbac-audit diff before.json after.json`
    Then the command exits <exit code>

    Examples:
      | change                                            | exit code |
      | adds a ClusterRoleBinding of cluster-admin        | 2         |
      | adds a binding to Group system:masters            | 2         |
      | changes nothing                                   | 0         |
      | has violations only from rules set to fail: false | 0         |

  @id:policy.gating.002 @rule:policy.gating.no-policy-report-only @verified @source:rbac_audit.py#load_policy_for @test:tests/test_cli.py#test_no_policy_shows_what_would_have_blocked @test:tests/test_cli.py#test_no_policy_works_the_same_way
  Scenario Outline: With --no-policy, violations are reported as warnings and never fail the run
    Given after.json adds ClusterRoleBinding ci-admin to cluster-admin
    When the operator runs `rbac-audit <command> --no-policy`
    Then the report lists Policy violations, each marked (warn), including cluster-admin-binding on ClusterRoleBinding/ci-admin
    And the summary line says (none gating)
    And the command exits 0

    Examples:
      | command                     |
      | diff before.json after.json |
      | baseline after.json         |
