@domain:policy @area:gating @from:rbac-auditor/rbac-audit-policy
Feature: Deciding whether findings fail the build
  Turns findings into a pass/fail verdict CI can act on, and keeps the report readable by collapsing repeats.

  @id:policy.gating.003 @rule:policy.gating.blocking-finding-fails-build @verified @source:rbac_audit_policy.py#gating @test:tests/test_policy.py#test_a_new_cluster_admin_binding_fails @test:tests/test_policy.py#test_an_unmounted_account_warns @test:tests/test_policy.py#test_fail_false_reports_without_gating
  Scenario Outline: Only a finding from a blocking rule fails the build
    Given the audit's findings are <findings>
    When the operator audits the change
    Then the process exits with code <exit>

    Examples:
      | findings                                                        | exit |
      | a cluster-admin-binding finding under the default policy        | 2    |
      | only an unused-service-account finding under the default policy | 0    |
      | a wildcard finding with wildcard set to fail: false             | 0    |
      | only exempted findings                                          | 0    |
      | none                                                            | 0    |

  @id:policy.gating.004 @rule:policy.gating.repeated-findings-collapse @verified @source:rbac_audit_policy.py#collapse_violations @test:tests/test_policy.py#test_one_rule_yields_one_finding_per_reason_not_per_grant @test:tests/test_policy.py#test_distinct_escalating_verbs_stay_distinct
  Scenario Outline: Repeated findings about the same object collapse into one with a count
    Given the default policy is in effect
    And a change that <change>
    When the operator audits the change
    Then the audit reports <count> finding(s) for that role
    And <collapsed>

    Examples:
      | change                                                                             | count | collapsed                                 |
      | adds a ClusterRole r granting get, list on pods, secrets, configmaps in apiGroup * | 1     | the wildcard finding notes 5 more like it |
      | adds a ClusterRole r granting bind, escalate on roles.rbac.authorization.k8s.io    | 2     | one escalating-verbs finding per verb     |
