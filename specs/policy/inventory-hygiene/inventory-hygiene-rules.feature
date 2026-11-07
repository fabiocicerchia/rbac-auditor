@domain:policy @area:inventory-hygiene @from:rbac-auditor/rbac-audit-policy
Feature: Catching bindings and ServiceAccounts that do not line up with the cluster
  Warns operators about latent grants to ServiceAccounts that do not exist and about credentials no workload uses, and says plainly when it could not check.

  Background:
    Given the default policy is in effect

  @id:policy.inventory-hygiene.001 @rule:policy.inventory.dangling-binding-blocks @verified @source:rbac_audit_policy.py#check_dangling_binding @test:tests/test_policy.py#test_a_binding_to_a_missing_service_account_fires @questionable
  Scenario: A binding to a ServiceAccount that does not exist blocks the build
    Given no ServiceAccount apps/grafana exists in the snapshot being judged
    When the operator audits a change that adds a ClusterRoleBinding b binding ServiceAccount apps/grafana to view
    Then the audit reports a blocking dangling-binding finding
    And the finding reads "names ServiceAccount apps/grafana, which does not exist — creating it would grant ClusterRole/view"

  @id:policy.inventory-hygiene.002 @rule:policy.inventory.dangling-binding-not-fired @verified @source:rbac_audit_policy.py#check_dangling_binding @test:tests/test_policy.py#test_a_binding_to_an_existing_service_account_does_not_fire @test:tests/test_policy.py#test_a_user_or_group_subject_is_never_dangling @test:tests/test_policy.py#test_deleting_a_dangling_binding_does_not_fire @test:tests/test_policy.py#test_creating_the_missing_account_clears_it
  Scenario Outline: Bindings to existing ServiceAccounts, users or groups are not dangling
    Given a change that <change>
    When the operator audits the change
    Then the audit reports no dangling-binding finding

    Examples:
      | change                                                                          |
      | adds a binding to ServiceAccount apps/grafana together with that ServiceAccount |
      | adds a binding to User alice@example.com                                        |
      | adds a binding to Group sre                                                     |
      | deletes a binding to the missing ServiceAccount apps/grafana                    |
      | creates the missing ServiceAccount apps/grafana for an existing binding         |

  @id:policy.inventory-hygiene.003 @rule:policy.inventory.unused-service-account-warns @verified @source:rbac_audit_policy.py#check_unused_service_account @test:tests/test_policy.py#test_an_unmounted_account_warns @test:tests/test_policy.py#test_a_mounted_account_does_not_warn @test:tests/test_policy.py#test_default_is_never_unused @test:tests/test_policy.py#test_deleting_an_unused_account_does_not_warn
  Scenario Outline: A new ServiceAccount no pod mounts is reported as a warning
    Given the audit runs against a live cluster
    And a change that adds ServiceAccount <account>
    And <mounted>
    When the operator audits the change
    Then the audit reports <outcome>
    And the build is not failed by it

    Examples:
      | account              | mounted          | outcome                                                                                                         |
      | staging/old-migrator | no pod mounts it | a non-blocking unused-service-account finding "no pod mounts staging/old-migrator — a token nobody is watching" |
      | ci/deployer          | a pod mounts it  | no findings                                                                                                     |
      | ci/default           | no pod mounts it | no findings                                                                                                     |

  @id:policy.inventory-hygiene.004 @rule:policy.inventory.unrunnable-rule-not-checked @verified @source:rbac_audit_policy.py#runnable_rules @test:tests/test_policy.py#test_it_is_skipped_rather_than_passed_without_pods
  Scenario: Without a live cluster the unused-ServiceAccount rule is reported as not checked
    Given the audit judges snapshot files only, with no live cluster
    And a change that adds ServiceAccount staging/old-migrator
    When the operator audits the change
    Then the audit reports no unused-service-account finding
    And unused-service-account is listed under "Not checked" because it needs the cluster's pods, which a snapshot does not carry
