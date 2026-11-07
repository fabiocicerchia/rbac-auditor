@domain:snapshots @area:snapshot-validation @from:rbac-auditor/rbac-audit
Feature: Loading snapshot files
  Protects the security gate from bad input: a file that is not a valid snapshot stops the run with a clear reason instead of being read as an empty cluster.

  @id:snapshots.snapshot-validation.001 @rule:snapshots.validation.diff-report-refused @verified @source:rbac_audit.py#validate_snapshot @test:tests/test_cli.py#test_a_json_diff_report_is_refused_as_a_snapshot
  Scenario: A JSON diff report is refused when given as a snapshot
    Given drift.json was written by `rbac-audit diff before.json after.json --json drift.json`
    When the operator runs `rbac-audit diff drift.json after.json`
    Then the command exits 65
    And stderr says the kind is RbacDiff and this looks like a --json diff report, not a snapshot

  @id:snapshots.snapshot-validation.002 @rule:snapshots.validation.unusable-file-refused @verified @source:rbac_audit.py#load_snapshot @test:tests/test_cli.py#test_a_missing_snapshot_exits_66 @test:tests/test_cli.py#test_a_snapshot_that_is_not_json_exits_65 @test:tests/test_cli.py#test_a_file_that_is_not_a_snapshot_exits_65 @test:tests/test_cli.py#test_a_section_that_is_not_a_list @test:tests/test_cli.py#test_an_item_that_is_not_an_object @test:tests/test_cli.py#test_an_item_with_no_name @test:tests/test_cli.py#test_rules_that_are_not_a_list @test:tests/test_cli.py#test_a_rule_field_that_is_not_a_list_of_strings @test:tests/test_cli.py#test_a_role_ref_that_is_not_an_object @test:tests/test_cli.py#test_subjects_that_are_not_objects
  Scenario Outline: A snapshot file that is missing or malformed stops the run
    Given the OLD snapshot file is <problem>
    When the operator runs `rbac-audit diff OLD after.json`
    Then the command exits <exit code>
    And stderr names the file and what is wrong with it

    Examples:
      | problem                                           | exit code |
      | missing                                           | 66        |
      | not JSON                                          | 65        |
      | an empty JSON object with no kind                 | 65        |
      | of an apiVersion other than rbac-audit/v1         | 65        |
      | holding a clusterRoles section that is not a list | 65        |
      | holding a ClusterRole that is not an object       | 65        |
      | holding a ClusterRole with no name                | 65        |
      | holding a ClusterRole whose rules are not a list  | 65        |
      | holding a rule whose verbs are not strings        | 65        |
      | holding a binding whose roleRef is not an object  | 65        |
      | holding a binding whose subjects are not objects  | 65        |

  @id:snapshots.snapshot-validation.003 @rule:snapshots.validation.missing-section-read-as-empty @gap @source:rbac_audit.py#load_snapshot @questionable
  Scenario: A snapshot that leaves out a section is read as having none of that kind
    Given a hand-edited after.json is a valid RbacSnapshot that has no clusterRoleBindings section at all
    And before.json holds ClusterRoleBinding ci-admin
    When the operator runs `rbac-audit diff before.json after.json`
    Then the file is accepted
    And ClusterRoleBinding/ci-admin is reported as removed
