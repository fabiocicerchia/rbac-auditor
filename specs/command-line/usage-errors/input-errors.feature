@domain:command-line @area:usage-errors @from:rbac-auditor/rbac-audit
Feature: Rejecting bad input with distinct exit codes
  Ensures CI can tell a typo or broken input apart from a security finding, because each failure has its own exit code and none reuses the gate's 2.

  @id:command-line.usage-errors.001 @rule:cli.usage.usage-error-is-64 @verified @source:rbac_audit.py#Parser @test:tests/test_cli.py#test_a_usage_error_exits_64_not_2
  Scenario: A command-line mistake exits 64, never the policy code 2
    Given the operator omits the OLD snapshot that diff requires
    When the operator runs `rbac-audit diff`
    Then usage is printed on stderr
    And the command exits 64

  @id:command-line.usage-errors.002 @rule:cli.usage.policy-file-errors @verified @source:rbac_audit.py#load_policy @test:tests/test_cli.py#test_a_missing_policy_file_exits_66 @test:tests/test_cli.py#test_an_unparsable_policy_exits_65 @test:tests/test_cli.py#test_an_unreadable_policy_is_65_before_the_cluster_is_read
  Scenario Outline: A policy file that is missing or invalid stops the run before the cluster is read
    Given the policy file policy.yaml <problem>
    And no NEW snapshot is given, so the live cluster would be read
    When the operator runs `rbac-audit diff before.json --policy policy.yaml`
    Then the command exits <exit code> without reading the cluster
    And stderr names the file and the problem

    Examples:
      | problem                                 | exit code |
      | does not exist                          | 66        |
      | is not valid YAML                       | 65        |
      | names a rule that does not exist        | 65        |
      | sets a setting the rule does not accept | 65        |

  @id:command-line.usage-errors.003 @rule:cli.usage.default-policy-file @gap @source:rbac_audit.py#load_policy
  Scenario Outline: Without --policy, ./.rbac-policy.yaml is used if present, otherwise the built-in defaults
    Given the working directory <has policy>
    When the operator runs `rbac-audit diff before.json after.json`
    Then the run is judged by <policy used>

    Examples:
      | has policy                 | policy used                                |
      | contains .rbac-policy.yaml | that file merged with the defaults         |
      | has no .rbac-policy.yaml   | the built-in default policy, with no error |

  @id:command-line.usage-errors.004 @rule:cli.usage.unwritable-output-73 @gap @source:rbac_audit.py#write_out
  Scenario: An output file that cannot be written exits 73
    Given the path /readonly/snap.json cannot be written
    When the operator runs `rbac-audit snapshot -o /readonly/snap.json` or passes it to --json
    Then stderr says cannot write /readonly/snap.json
    And the command exits 73
