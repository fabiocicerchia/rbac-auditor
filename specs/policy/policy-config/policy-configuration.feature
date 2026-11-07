@domain:policy @area:policy-config @from:rbac-auditor/rbac-audit-policy
Feature: Configuring the audit policy
  Lets a platform team tune which RBAC rules run and what they watch, while refusing any policy file the gate cannot read unambiguously.

  @id:policy.policy-config.001 @rule:policy.config.secure-defaults @verified @source:rbac_audit_policy.py#DEFAULT_POLICY @test:tests/test_policy.py#test_defaults_are_on @test:tests/test_policy.py#test_escalation_rules_block_and_only_hygiene_warns @test:tests/test_policy.py#test_default_is_never_unused
  Scenario: Without a policy file every rule runs and all but the unused-ServiceAccount rule block
    Given no policy file is present
    When the operator audits the cluster
    Then the rules cluster-admin-binding, wildcard, escalating-verbs, anonymous-subject, masters-subject, dangling-binding and unused-service-account are all enabled
    And every rule except unused-service-account fails the build when it fires
    And unused-service-account only warns
    And unused-service-account ignores the ServiceAccount named "default"

  @id:policy.policy-config.002 @rule:policy.config.malformed-policy-refused @verified @source:rbac_audit_policy.py#merge_policy @test:tests/test_policy.py#test_unknown_rule_name_is_fatal @test:tests/test_policy.py#test_unknown_setting_is_fatal @test:tests/test_policy.py#test_unknown_top_level_key_is_fatal @test:tests/test_policy.py#test_unsupported_version_is_fatal @test:tests/test_policy.py#test_a_scalar_where_a_list_belongs_is_fatal @test:tests/test_policy.py#test_a_scalar_roles_list_cannot_become_a_substring_match @test:tests/test_policy.py#test_a_null_list_is_fatal @test:tests/test_policy.py#test_a_non_bool_enabled_is_fatal
  Scenario Outline: A policy file the gate cannot read unambiguously is refused
    Given a policy file containing <content>
    When the operator runs the audit with that policy
    Then the audit stops before judging any change
    And the error names the problem: <message>
    And the process exits with code 65

    Examples:
      | content                                  | message                                                              |
      | rules: {wildcards: {enabled: false}}     | unknown policy rule 'wildcards' (known rules: ...)                   |
      | rules: {wildcard: {enable: false}}       | rule 'wildcard': unknown setting(s) enable                           |
      | ruls: {}                                 | unknown key(s): ruls                                                 |
      | version: 2                               | unsupported policy version 2, expected 1                             |
      | rules: {escalating-verbs: {verbs: bind}} | rule 'escalating-verbs': verbs must be a list of strings, got 'bind' |
      | rules: {wildcard: {fields: null}}        | rule 'wildcard': fields must be a list of strings, got None          |
      | rules: {wildcard: {enabled: "no"}}       | rule 'wildcard': enabled must be true or false, got 'no'             |
      | a YAML list instead of a mapping         | policy must be a YAML mapping                                        |

  @id:policy.policy-config.003 @rule:policy.config.rule-watch-lists-configurable @verified @source:rbac_audit_policy.py#merge_policy @test:tests/test_policy.py#test_the_subjects_list_is_configurable @test:tests/test_policy.py#test_the_ignore_list_is_configurable @test:tests/test_policy.py#test_narrowing_the_watched_fields
  Scenario Outline: A rule watches what the policy file tells it to watch
    Given a policy file setting <rule> <setting> to <value>
    And a change that <change>
    When the operator audits the change
    Then the audit reports <outcome>

    Examples:
      | rule                   | setting  | value                  | change                                            | outcome                   |
      | masters-subject        | subjects | [corp:breakglass]      | binds Group corp:breakglass to ClusterRole/view   | a masters-subject finding |
      | unused-service-account | ignore   | [default, builder]     | adds ServiceAccount ci/builder that no pod mounts | no finding                |
      | wildcard               | fields   | [resources, apiGroups] | grants verb * on pods.apps                        | no finding                |

  @id:policy.policy-config.004 @rule:policy.config.disabled-rule-is-silent @verified @source:rbac_audit_policy.py#runnable_rules @test:tests/test_policy.py#test_disabled_rule_stops_looking @test:tests/test_policy.py#test_a_disabled_rule_is_not_reported_as_skipped
  Scenario Outline: A disabled rule reports nothing and is not listed as not checked
    Given a policy file setting <rule> enabled to false
    And a change that <change>
    When the operator audits the change
    Then the audit reports no <rule> finding
    And <rule> is not listed under "Not checked"

    Examples:
      | rule                   | change                                                                          |
      | wildcard               | adds ClusterRole system:controller:x granting * on *.*                          |
      | unused-service-account | adds ServiceAccount staging/old-migrator with no live cluster to read pods from |
