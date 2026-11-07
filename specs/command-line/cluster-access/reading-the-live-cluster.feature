@domain:command-line @area:cluster-access @from:rbac-auditor/rbac-audit
Feature: Reading RBAC from the live cluster
  Lets an operator capture or judge the RBAC of the cluster in a kubeconfig context through read-only kubectl calls, and get a clear failure when the cluster cannot be reached.

  @id:command-line.cluster-access.001 @rule:snapshots.live.reads-named-context @verified @source:rbac_audit.py#capture @test:tests/test_integration.py#test_snapshot_reads_every_section_from_the_named_context
  Scenario: A live snapshot reads every RBAC kind from the chosen context
    Given kubeconfig context staging reaches a cluster with ClusterRoles, Roles, bindings and ServiceAccounts
    When the operator runs `rbac-audit snapshot --context staging -o snap.json`
    Then the command exits 0
    And kubectl is asked only to get clusterroles, roles, clusterrolebindings, rolebindings and serviceaccounts across all namespaces in context staging
    And snap.json records the roles, bindings and ServiceAccounts without server-assigned fields such as uid

  @id:command-line.cluster-access.002 @rule:cli.cluster.unreachable-exits-69 @verified @source:rbac_audit.py#kubectl_json @test:tests/test_integration.py#test_a_failing_kubectl_exits_unavailable_with_its_error @test:tests/test_cli.py#test_a_missing_kubectl_is_a_message_not_a_traceback
  Scenario Outline: A cluster that cannot be read stops the run with exit 69 and kubectl's reason
    Given <situation>
    When the operator runs `rbac-audit snapshot`
    Then the command exits 69
    And stderr says <message>
    And nothing is written to stdout

    Examples:
      | situation                                                | message                                                           |
      | kubectl fails to get roles with "no resource type roles" | kubectl get roles failed: ... no resource type roles              |
      | kubectl is not installed                                 | kubectl is not on PATH, and that a two-file diff does not need it |

  @id:command-line.cluster-access.003 @rule:cli.cluster.files-only-diff-needs-no-cluster @verified @source:rbac_audit.py#read_target @test:tests/test_cli.py#test_a_two_file_diff_never_calls_kubectl
  Scenario: Diffing two snapshot files never touches a cluster
    Given two committed snapshots before.json and after.json
    And no cluster is reachable
    When the operator runs `rbac-audit diff before.json after.json`
    Then kubectl is never invoked
    And the command exits by the policy verdict alone

  @id:command-line.cluster-access.004 @rule:cli.cluster.diff-defaults-to-live @verified @source:rbac_audit.py#run_diff @test:tests/test_integration.py#test_a_live_snapshot_is_stable_and_diffs_clean_against_itself
  Scenario: A diff with one snapshot compares it to the live cluster
    Given a.json was snapshotted from the cluster in the current context, which has not changed since
    When the operator runs `rbac-audit diff a.json`
    Then the report is headed RBAC diff — a.json → live cluster
    And it says No changes.
    And the command exits 0

  @id:command-line.cluster-access.005 @rule:cli.cluster.one-source-per-snapshot @verified @source:rbac_audit.py#run_snapshot @test:tests/test_cli.py#test_context_and_from_manifests_together_are_refused
  Scenario: A snapshot cannot be taken from manifests and a cluster context at once
    Given a manifests directory and a kubeconfig context prod
    When the operator runs `rbac-audit snapshot --from-manifests DIR --context prod`
    Then the command exits 64
    And stderr says --from-manifests reads files, --context reads a cluster, pick one
