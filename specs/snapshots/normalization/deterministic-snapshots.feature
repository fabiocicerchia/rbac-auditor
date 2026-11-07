@domain:snapshots @area:normalization @from:rbac-auditor/rbac-audit
Feature: Committable, deterministic snapshots
  Serves teams who commit snapshots and review them week over week: the same RBAC must always produce the same bytes, so a diff only ever shows real change.

  @id:snapshots.normalization.001 @rule:snapshots.normalization.byte-stable @verified @source:rbac_audit.py#dump_snapshot @test:tests/test_integration.py#test_a_live_snapshot_is_stable_and_diffs_clean_against_itself @test:tests/test_cli.py#test_the_same_tree_gives_the_same_bytes @test:tests/test_cli.py#test_it_is_the_committed_format_and_reloads_as_a_snapshot @test:tests/test_snapshot.py#test_round_trip_is_byte_stable @test:tests/test_snapshot.py#test_ends_in_a_newline @test:tests/test_snapshot.py#test_key_order_does_not_depend_on_input_order
  Scenario: The same RBAC always produces a byte-identical snapshot
    Given a cluster or manifest tree whose RBAC has not changed
    When the operator snapshots it twice
    Then the two files are byte-identical
    And keys are sorted, indented two spaces, and the file ends in a newline
    And reloading and re-writing a snapshot reproduces the same bytes

  @id:snapshots.normalization.002 @rule:snapshots.normalization.no-timestamp-no-pods @verified @source:rbac_audit.py#dump_snapshot @test:tests/test_snapshot.py#test_payload_carries_no_timestamp @test:tests/test_snapshot.py#test_pods_are_not_in_the_snapshot
  Scenario: A snapshot carries no timestamp and no pods
    Given a cluster whose pods are replaced on every rollout
    When the operator snapshots it
    Then the file records no time it was taken
    And the file has no pods section, so a rollout alone never changes it

  @id:snapshots.normalization.003 @rule:snapshots.normalization.equivalent-spellings-no-drift @verified @source:rbac_audit.py#normalize_binding @test:tests/test_snapshot.py#test_rule_order_does_not_matter @test:tests/test_snapshot.py#test_lists_are_sorted_and_deduplicated @test:tests/test_snapshot.py#test_service_account_namespace_is_made_explicit @test:tests/test_snapshot.py#test_role_ref_keeps_only_kind_and_name
  Scenario Outline: Rewriting RBAC into an equivalent spelling is not reported as drift
    Given the committed snapshot holds a role or binding
    And the cluster now holds the same object <rewritten>
    When the operator diffs the committed snapshot against a fresh snapshot
    Then both snapshots record the object identically
    And the report says No changes.

    Examples:
      | rewritten                                                                                   |
      | with its rules in a different order                                                         |
      | with duplicated and unsorted verbs                                                          |
      | with a ServiceAccount subject's namespace spelled out instead of implied by the RoleBinding |
      | with roleRef apiGroup omitted                                                               |
