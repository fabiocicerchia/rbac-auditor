@domain:drift-detection @area:grant-analysis @from:rbac-auditor/rbac-audit
Feature: Judging only genuinely new access
  Spares teams false alarms: the gate judges what a subject can newly do, so tightening or refactoring a rule never fails a build while any real widening does.

  Background:
    Givena Role whose rules change between the committed snapshot and the new one

  @id:drift-detection.grant-analysis.001 @rule:drift.grants.tightening-is-not-new-access @verified @source:rbac_audit.py#grant_delta @test:tests/test_diff.py#test_a_broad_grant_implies_a_narrow_one @test:tests/test_diff.py#test_narrowing_a_rule_adds_no_grants @test:tests/test_diff.py#test_splitting_one_rule_into_two_adds_no_grants
  Scenario Outline: Tightening or restructuring a rule grants nothing new
    Given the role's rules change from <before> to <after>
    When the operator diffs the two snapshots
    Then the role's change counts 0 grants added
    And no policy rule fires on access the role already allowed

    Examples:
      | before                               | after                                 |
      | * apiGroups, * resources, verb get   | * apiGroups, resources pods, verb get |
      | pods, verbs *                        | pods, verbs get and list              |
      | pods in apiGroups *                  | pods in apiGroup apps                 |
      | get secrets                          | get secrets with resourceNames db     |
      | get nonResourceURL /api/*            | get nonResourceURL /api/v1            |
      | roles, verbs bind, get, list         | roles, verb bind                      |
      | pods, verbs get and list in one rule | the same split across two rules       |

  @id:drift-detection.grant-analysis.002 @rule:drift.grants.widening-is-new-access @verified @source:rbac_audit.py#new_grants @test:tests/test_diff.py#test_a_narrow_grant_does_not_imply_a_broad_one @test:tests/test_cli.py#test_the_report_carries_grant_counts_not_every_grant
  Scenario: Widening a rule is counted as new access
    Given the role's rules change from get pods in the core group to * on * in apiGroups *
    When the operator diffs the two snapshots with --json
    Then the role's change reports grantCounts added 1
    And the narrower grant it replaced does not hide the new one
