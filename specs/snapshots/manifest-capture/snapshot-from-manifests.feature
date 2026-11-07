@domain:snapshots @area:manifest-capture @from:rbac-auditor/rbac-audit
Feature: Snapshotting RBAC from manifests
  Lets an operator snapshot the RBAC a pull request proposes straight from its YAML/JSON files, with no cluster, so the gate can run before anything is applied.

  Background:
    Givena directory of Kubernetes manifests the operator proposes to apply

  @id:snapshots.manifest-capture.001 @rule:snapshots.manifests.rbac-kinds-only @verified @source:rbac_audit.py#capture_manifests @test:tests/test_cli.py#test_it_keeps_rbac_and_service_accounts_and_nothing_else @test:tests/test_cli.py#test_kubectl_is_never_called @test:tests/test_cli.py#test_a_json_manifest_is_read_like_kubectl_reads_it @test:tests/test_cli.py#test_a_kind_list_is_unwrapped
  Scenario: A manifest snapshot holds the RBAC objects and ServiceAccounts kubectl would apply, and nothing else
    Given the directory holds a Role, a RoleBinding, a ClusterRoleBinding and two ServiceAccounts across .yaml, .yml and .json files and a kind: List
    And it also holds a ConfigMap and a Role from a non-RBAC API group
    When the operator runs `rbac-audit snapshot --from-manifests DIR -o pr.json`
    Then the command exits 0 without calling kubectl
    And pr.json is an RbacSnapshot of apiVersion rbac-audit/v1 listing the RBAC objects and ServiceAccounts
    And the ConfigMap and the non-RBAC Role are left out without a warning
    And a ServiceAccount subject without a namespace takes its RoleBinding's namespace

  @id:snapshots.manifest-capture.002 @rule:snapshots.manifests.duplicate-object-refused @verified @source:rbac_audit.py#capture_manifests @test:tests/test_cli.py#test_an_object_defined_twice_is_a_data_error @test:tests/test_cli.py#test_a_namespace_on_a_cluster_scoped_object_is_dropped
  Scenario: An object defined twice in the manifests is refused
    Given ClusterRole x is defined in both a.yaml and b.yaml, possibly differing only in a namespace the API server would drop
    When the operator snapshots the directory with --from-manifests
    Then the command exits 65
    And the error names the object and both files it is defined in
    And no snapshot is written

  @id:snapshots.manifest-capture.003 @rule:snapshots.manifests.unset-namespace-is-default @verified @source:rbac_audit.py#_as_applied @test:tests/test_cli.py#test_an_empty_or_null_namespace_is_default
  Scenario: A namespaced object with no namespace is recorded in the default namespace
    Given two ServiceAccounts a and b, one with an empty namespace and one with a null namespace
    When the operator snapshots the directory with --from-manifests
    Then the command exits 0
    And both ServiceAccounts are recorded in namespace default

  @id:snapshots.manifest-capture.004 @rule:snapshots.manifests.aggregation-resolved @verified @source:rbac_audit.py#_aggregate @test:tests/test_cli.py#test_an_aggregated_role_holds_its_contributors_rules @test:tests/test_cli.py#test_a_label_that_joins_an_aggregate_fails_the_gate @test:tests/test_cli.py#test_aggregation_reads_selectors_as_kubernetes_does
  Scenario: An aggregated ClusterRole is snapshotted with the rules of every role its selectors match
    Given ClusterRole team-admin aggregates roles labelled acme.io/to-team-admin=true and is bound to Group devs
    And the committed snapshot was taken while ClusterRole anything, granting * on *, lacked that label
    When the operator diffs the committed snapshot against a manifest snapshot in which anything carries the label
    Then team-admin holds anything's rules in the new snapshot
    And the report lists [wildcard] ClusterRole/team-admin
    And the command exits 2

  @id:snapshots.manifest-capture.005 @rule:snapshots.manifests.unjudgeable-aggregate-warned @verified @source:rbac_audit.py#_warn_unselected_contributors @test:tests/test_cli.py#test_a_contributor_to_a_role_outside_the_tree_is_reported
  Scenario: A role that feeds an aggregate outside the manifests is warned about, not passed silently
    Given ClusterRole crd-admin is labelled rbac.authorization.k8s.io/aggregate-to-admin: "true"
    And no ClusterRole in the directory selects it
    When the operator snapshots the directory with --from-manifests
    Then the command exits 0
    And a warning on stderr names ClusterRole/crd-admin and says the gate cannot judge the role it reaches

  @id:snapshots.manifest-capture.006 @rule:snapshots.manifests.unreadable-input-refused @verified @source:rbac_audit.py#run_snapshot @test:tests/test_cli.py#test_a_missing_directory_is_no_input @test:tests/test_cli.py#test_a_directory_that_cannot_be_listed_is_no_input @test:tests/test_cli.py#test_broken_yaml_is_a_data_error @test:tests/test_cli.py#test_a_file_that_is_not_text_is_a_data_error @test:tests/test_cli.py#test_a_json_manifest_is_read_like_kubectl_reads_it @test:tests/test_cli.py#test_malformed_identity_fields_are_data_errors @test:tests/test_cli.py#test_aggregation_reads_selectors_as_kubernetes_does @test:tests/test_cli.py#test_json_nested_past_the_recursion_limit_is_a_data_error
  Scenario Outline: A manifest directory that cannot be fully read is refused rather than partly snapshotted
    Given the manifest directory has <problem>
    When the operator snapshots the directory with --from-manifests
    Then the command exits <exit code>
    And an error on stderr names the path and the problem
    And no snapshot is written

    Examples:
      | problem                                          | exit code |
      | no such directory                                | 66        |
      | a subdirectory that cannot be listed             | 66        |
      | a .yaml file that does not parse                 | 65        |
      | a .yaml file that is not text                    | 65        |
      | a .json file that is not JSON                    | 65        |
      | a Role with an empty metadata.name               | 65        |
      | a kind that is not a string                      | 65        |
      | a Role whose namespace is not a string           | 65        |
      | an aggregation selector with an unknown operator | 65        |
