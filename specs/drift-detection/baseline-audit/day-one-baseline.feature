@domain:drift-detection @area:baseline-audit @from:rbac-auditor/rbac-audit
Feature: Auditing a whole cluster on day one
  Gives an operator a full policy audit of an existing cluster or snapshot before any history exists, using the same rules that later judge drift.

  @id:drift-detection.baseline-audit.001 @rule:drift.baseline.whole-cluster-judged @verified @source:rbac_audit.py#run_baseline @test:tests/test_cli.py#test_it_judges_a_whole_snapshot
  Scenario: A baseline reports every standing problem, not just recent changes
    Given after.json binds a ServiceAccount to cluster-admin and binds Group system:unauthenticated to ClusterRole view
    When the operator runs `rbac-audit baseline after.json`
    Then the report is headed RBAC baseline — after.json
    And every object is listed as added, including ClusterRole/cluster-admin
    And cluster-admin-binding and anonymous-subject violations are reported
    And the command exits 2

  @id:drift-detection.baseline-audit.002 @rule:drift.baseline.clean-passes @verified @source:rbac_audit.py#run_baseline @test:tests/test_cli.py#test_a_clean_cluster_baselines_clean
  Scenario: A cluster with no RBAC baselines clean
    Given clean.json is a snapshot with every section empty
    When the operator runs `rbac-audit baseline clean.json`
    Then the report says No changes.
    And the command exits 0

  @id:drift-detection.baseline-audit.003 @rule:drift.baseline.reported-from-empty-cluster @verified @source:rbac_audit.py#report_and_exit @test:tests/test_cli.py#test_the_machine_report_names_them_too
  Scenario: A baseline's machine report says it was compared from an empty cluster
    Given the snapshot after.json
    When the operator runs `rbac-audit baseline after.json --json b.json`
    Then b.json has from set to "an empty cluster"
    And b.json has to set to after.json

  @id:drift-detection.baseline-audit.004 @rule:drift.baseline.live-cluster-default @verified @source:rbac_audit.py#read_target @test:tests/test_cli.py#test_it_reads_the_live_cluster_when_given_no_file @test:tests/test_integration.py#test_baseline_checks_unused_service_accounts_against_the_pods
  Scenario: A baseline without a file audits the live cluster, including its pods
    Given the cluster in the current context has a ServiceAccount ci/idle that no pod runs as
    When the operator runs `rbac-audit baseline --json -`
    Then the cluster's RBAC and its pods are read
    And the report lists unused-service-account for ServiceAccount/ci/idle
    And no rule is listed as not checked
