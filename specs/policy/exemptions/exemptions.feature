@domain:policy @area:exemptions @from:rbac-auditor/rbac-audit-policy
Feature: Exempting accepted findings
  Lets an operator accept a known finding with a stated reason so it stays visible in the report but no longer blocks, without switching the rule off elsewhere.

  @id:policy.exemptions.001 @rule:policy.exemptions.exempted-finding-reported-not-blocking @verified @source:rbac_audit_policy.py#evaluate @test:tests/test_policy.py#test_exemption_keeps_the_rule_working_elsewhere @test:tests/test_policy.py#test_an_exemption_matches_by_subject
  Scenario Outline: An exempted finding is reported with its reason and does not block
    Given a policy exemption with <match> and reason "<reason>"
    And a change that <change>
    When the operator audits the change
    Then the <rule> finding is listed as exempted with reason "<reason>"
    And no blocking finding remains for it

    Examples:
      | match                                                    | reason                | change                                                                  | rule                  |
      | rule wildcard, object ClusterRole/system:*               | ships with Kubernetes | adds ClusterRole system:controller:x granting * on *.*                  | wildcard              |
      | rule masters-subject, subject Group system:masters       | the bootstrap group   | adds ClusterRoleBinding x binding Group system:masters to cluster-admin | masters-subject       |
      | rule cluster-admin-binding, subject Group system:masters | the bootstrap group   | adds ClusterRoleBinding x binding Group system:masters to cluster-admin | cluster-admin-binding |

  @id:policy.exemptions.002 @rule:policy.exemptions.scoped-to-named-fields @verified @source:rbac_audit_policy.py#exempted_by @test:tests/test_policy.py#test_exemption_keeps_the_rule_working_elsewhere @test:tests/test_policy.py#test_the_example_exempts_only_the_bootstrap_masters_binding
  Scenario Outline: An exemption covers only what its fields name
    Given a policy exemption with <match> and a reason
    And a change that <change>
    When the operator audits the change
    Then the audit reports <outcome>

    Examples:
      | match                                      | change                                                                             | outcome                                                                  |
      | rule wildcard, object ClusterRole/system:* | adds ClusterRole app granting get on x in apiGroup *                               | a blocking wildcard finding on ClusterRole/app                           |
      | object ClusterRoleBinding/cluster-admin    | binds system:masters via cluster-admin to cluster-admin, via breakglass to view    | a blocking masters-subject finding on ClusterRoleBinding/breakglass only |
      | object ClusterRole/system:*                | adds ClusterRole system:controller:x granting * on *.*                             | every finding on that role exempted                                      |

  @id:policy.exemptions.003 @rule:policy.exemptions.must-state-reason-and-match @verified @source:rbac_audit_policy.py#_check_exemption @test:tests/test_policy.py#test_an_exemption_needs_a_reason @test:tests/test_policy.py#test_an_exemption_needs_something_to_match_on @test:tests/test_policy.py#test_a_non_string_exempt_value_is_fatal @test:tests/test_policy.py#test_a_non_string_reason_is_fatal
  Scenario Outline: An exemption without a reason or something to match on is refused
    Given a policy file whose exempt list contains <entry>
    When the operator runs the audit with that policy
    Then the audit stops with the error "<message>"
    And the process exits with code 65

    Examples:
      | entry                                 | message                                                |
      | {object: ClusterRole/x}               | exempt[1]: needs a reason                              |
      | {object: ClusterRole/x, reason: "  "} | exempt[1]: needs a reason                              |
      | {object: ClusterRole/x, reason: true} | exempt[1]: needs a reason                              |
      | {reason: just because}                | exempt[1]: needs at least one of rule, object, subject |
      | {object: [A, B], reason: x}           | exempt[1]: object must be a string, got ['A', 'B']     |
      | {namespace: ci, reason: x}            | exempt[1]: unknown key(s) namespace                    |
