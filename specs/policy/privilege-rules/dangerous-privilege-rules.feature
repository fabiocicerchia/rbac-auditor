@domain:policy @area:privilege-rules @from:rbac-auditor/rbac-audit-policy
Feature: Flagging dangerous privilege grants
  Blocks a change that newly hands out cluster-admin, wildcard access or the verbs that let a subject grant itself more, so privilege creep shows up in review.

  Background:
    Given the default policy is in effect

  @id:policy.privilege-rules.001 @rule:policy.privilege.cluster-admin-binding-blocks @verified @source:rbac_audit_policy.py#check_cluster_admin_binding @test:tests/test_policy.py#test_a_new_cluster_admin_binding_fails @test:tests/test_policy.py#test_a_new_subject_on_an_existing_binding_fails @test:tests/test_policy.py#test_repointing_a_binding_at_cluster_admin_still_fires
  Scenario Outline: Newly binding a subject to cluster-admin blocks the build
    Given a change that <change>
    When the operator audits the change
    Then the audit reports a blocking cluster-admin-binding finding
    And the finding reads "binds ServiceAccount ci/deployer to ClusterRole/cluster-admin"

    Examples:
      | change                                                                                            |
      | adds a ClusterRoleBinding binding ServiceAccount ci/deployer to cluster-admin                     |
      | adds ServiceAccount ci/deployer to an existing cluster-admin binding that already names Group sre |
      | re-points an existing binding naming ServiceAccount ci/deployer from view to cluster-admin        |

  @id:policy.privilege-rules.002 @rule:policy.privilege.wildcard-grant-blocks @verified @source:rbac_audit_policy.py#check_wildcard @test:tests/test_policy.py#test_wildcard_verbs @test:tests/test_policy.py#test_wildcard_resources @test:tests/test_policy.py#test_wildcard_api_groups
  Scenario Outline: A new grant with a wildcard verb, resource or API group blocks the build
    Given a change that adds a ClusterRole r granting verbs <verbs> on resources <resources> in apiGroups <apiGroups>
    When the operator audits the change
    Then the audit reports a blocking wildcard finding
    And the finding says the new grant has `*` in <field>

    Examples:
      | verbs | resources | apiGroups | field     |
      | [*]   | [pods]    | [""]      | verbs     |
      | [get] | [*]       | [""]      | resources |
      | [get] | [secrets] | [*]       | apiGroups |

  @id:policy.privilege-rules.003 @rule:policy.privilege.escalating-verb-blocks @verified @source:rbac_audit_policy.py#check_escalating_verbs @test:tests/test_policy.py#test_bind_escalate_impersonate_each_fire @test:tests/test_policy.py#test_widening_the_same_rule_still_fires
  Scenario Outline: A new grant of bind, escalate or impersonate blocks the build
    Given a change that adds a ClusterRole r granting verb <verb> on roles.rbac.authorization.k8s.io
    When the operator audits the change
    Then the audit reports a blocking escalating-verbs finding
    And the finding reads "new grant of <verb>: <verb> roles.rbac.authorization.k8s.io"

    Examples:
      | verb        |
      | bind        |
      | escalate    |
      | impersonate |

  @id:policy.privilege-rules.004 @rule:policy.privilege.wildcard-verb-reported-once @verified @source:rbac_audit_policy.py#check_escalating_verbs @test:tests/test_policy.py#test_a_wildcard_verb_is_left_to_the_wildcard_rule @questionable
  Scenario: A wildcard verb is reported once, as a wildcard, not also as an escalating verb
    Given a change that adds a ClusterRole r granting verb * on roles.rbac.authorization.k8s.io
    When the operator audits the change
    Then the audit reports a wildcard finding
    And the audit reports no escalating-verbs finding

  @id:policy.privilege-rules.005 @rule:policy.evaluation.only-additions-judged @verified @source:rbac_audit_policy.py#evaluate @test:tests/test_policy.py#test_removing_a_cluster_admin_binding_is_not_a_violation @test:tests/test_policy.py#test_dropping_verbs_from_an_escalating_rule_does_not_fire @test:tests/test_policy.py#test_dropping_resources_from_a_wildcard_rule_does_not_fire @test:tests/test_policy.py#test_adding_resource_names_to_a_wildcard_rule_does_not_fire @test:tests/test_policy.py#test_splitting_a_rule_in_two_does_not_fire @test:tests/test_policy.py#test_an_unchanged_binding_is_not_a_violation
  Scenario Outline: Removing or narrowing access never raises a finding
    Given a change that <change>
    When the operator audits the change
    Then the audit reports no findings

    Examples:
      | change                                                                           |
      | deletes a ClusterRoleBinding binding ServiceAccount ci/deployer to cluster-admin |
      | drops get and list from a rule granting bind, get, list on roles                 |
      | drops secrets from a rule granting get on pods and secrets in apiGroup *         |
      | restricts a rule granting get on secrets in apiGroup * to resourceNames [db]     |
      | splits a rule granting get, list on pods into two rules granting get and list    |
      | leaves an existing cluster-admin binding unchanged                               |

  @id:policy.privilege-rules.006 @rule:policy.privilege.ordinary-grant-not-flagged @verified @source:rbac_audit_policy.py#check_wildcard @test:tests/test_policy.py#test_a_binding_to_another_role_is_not_a_violation @test:tests/test_policy.py#test_a_named_grant_is_not_a_violation @test:tests/test_policy.py#test_ordinary_verbs_do_not_fire
  Scenario Outline: An ordinary named grant raises no privilege finding
    Given a change that <change>
    When the operator audits the change
    Then the audit reports no findings

    Examples:
      | change                                                                          |
      | adds a ClusterRoleBinding binding ServiceAccount ci/deployer to view            |
      | adds a ClusterRole granting get on pods.apps                                    |
      | adds a ClusterRole granting get, list, watch on roles.rbac.authorization.k8s.io |
