@domain:reporting @area:json-report @from:rbac-auditor/rbac-audit
Feature: Machine-readable diff report
  Gives CI and tooling a stable JSON report of the same run the human reads, safe to pipe and small enough to keep.

  Background:
    Giventhe committed snapshot before.json and a newer snapshot after.json

  @id:reporting.json-report.001 @rule:reporting.json.stdout-is-pure-json @verified @source:rbac_audit.py#report_and_exit @test:tests/test_cli.py#test_json_to_stdout_is_the_only_thing_on_stdout
  Scenario: With --json -, stdout carries only the JSON report
    Given after.json introduces policy violations
    When the operator runs `rbac-audit diff before.json after.json --json -`
    Then stdout parses as one JSON document
    And the human report is not printed
    And the command still exits 2

  @id:reporting.json-report.002 @rule:reporting.json.same-run-as-text @verified @source:rbac_audit.py#machine_report @test:tests/test_cli.py#test_json_and_text_come_from_the_same_run @test:tests/test_cli.py#test_machine_output_is_deterministic @test:tests/test_cli.py#test_a_json_diff_report_is_refused_as_a_snapshot
  Scenario: The JSON report agrees with the text report and is deterministic
    Given after.json introduces five violations
    When the operator runs `rbac-audit diff before.json after.json --json diff.json`
    Then diff.json has apiVersion rbac-audit/v1, kind RbacDiff, from before.json and to after.json
    And its summary violation count matches the text summary line and its violations list
    And its violations are anonymous-subject, cluster-admin-binding, escalating-verbs twice and wildcard
    And running it again gives byte-identical JSON

  @id:reporting.json-report.003 @rule:reporting.json.grant-counts-not-grants @verified @source:rbac_audit.py#public_change @test:tests/test_cli.py#test_the_report_carries_grant_counts_not_every_grant @test:tests/test_cli.py#test_a_binding_change_has_no_grant_counts
  Scenario: Changed roles carry grant counts, not every expanded grant
    Given Role ci/deploy gains patch on deployments, bind and escalate on roles, and get on secrets
    When the operator runs `rbac-audit diff before.json after.json --json diff.json`
    Then the Role/ci/deploy change has grantCounts added 4 and removed 0 and its rules, but no grants list
    And binding changes have newlyGranted and no grantCounts

  @id:reporting.json-report.004 @rule:reporting.json.subject-matrix-included @verified @source:rbac_audit.py#machine_report @test:tests/test_cli.py#test_the_subject_matrix_is_in_the_machine_output
  Scenario: A subject-scoped JSON report includes the subject and its matrix
    Given ServiceAccount ci/deployer gains patch on deployments
    When the operator runs `rbac-audit diff before.json after.json --subject ServiceAccount/ci/deployer --json -`
    Then the report has subject ServiceAccount/ci/deployer
    And its matrix lists verbs including patch and non-empty rows
