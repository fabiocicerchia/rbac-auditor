@domain:reporting @area:text-report @from:rbac-auditor/rbac-audit
Feature: Human-readable audit report
  Gives reviewers one report that says what changed, what the policy found, what was let through and why, and what could not be checked.

  @id:reporting.text-report.001 @rule:reporting.text.not-checked-listed @verified @source:rbac_audit.py#render_skipped @test:tests/test_cli.py#test_it_says_which_rules_it_could_not_run @test:tests/test_cli.py#test_the_machine_report_names_them_too @test:tests/test_cli.py#test_the_pull_request_gate
  Scenario: A rule that needs the live cluster is listed as not checked when judging files
    Given a snapshot file is judged with no cluster to read pods from
    When the operator runs `rbac-audit baseline after.json --json b.json`
    Then the report has a Not checked (1) section naming unused-service-account and that it needs a live cluster
    And b.json lists unused-service-account under notChecked
    And the result is still decided by the rules that did run

  @id:reporting.text-report.002 @rule:reporting.text.exempted-listed-with-reason @verified @source:rbac_audit.py#render_violations @test:tests/test_cli.py#test_an_exempting_policy_clears_the_gate
  Scenario: Exempted findings are listed with their reason while the verdict reads clean
    Given the policy exempts ClusterRoleBinding/ci-admin with reason "the CI deployer, reviewed 2026-09" and every other finding in after.json
    When the operator runs `rbac-audit diff before.json after.json --policy policy.yaml`
    Then the report says No policy violations.
    And an Exempted (n) section lists each exempted finding as [rule] object — reason
    And the summary line ends with n exempted
    And the command exits 0

  @id:reporting.text-report.003 @rule:reporting.text.summary-line @verified @source:rbac_audit.py#render_report @test:tests/test_cli.py#test_json_and_text_come_from_the_same_run
  Scenario: The report ends with a one-line count of changes and violations
    Given after.json adds, removes and changes objects and raises violations
    When the operator runs `rbac-audit diff before.json after.json`
    Then the last line reads "<a> added, <r> removed, <c> changed; <v> policy violations."
    And the violation count equals the number of violations listed above it
