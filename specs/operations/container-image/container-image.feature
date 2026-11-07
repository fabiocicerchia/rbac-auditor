@domain:operations @area:container-image @from:rbac-auditor/dockerfile
Feature: Running the auditor from its container image
  Lets operators and CI run the auditor, with a matching kubectl, from one image without installing anything, under a non-root identity.

  Background:
    Given the operator has the rbac-auditor container image

  @id:operations.container-image.001 @rule:operations.container-image.runs-auditor-default-snapshot @inferred @source:Dockerfile#ENTRYPOINT
  Scenario Outline: The image runs the auditor with the operator's arguments and takes a snapshot when given none
    Given the operator mounts the snapshot files they want to compare
    When the operator runs the image with <arguments>
    Then the auditor runs the <command> command
    And the exit code is the one that command reports

    Examples:
      | arguments                                       | command  |
      | no arguments                                    | snapshot |
      | diff /fixtures/before.json /fixtures/after.json | diff     |
      | baseline /fixtures/after.json                   | baseline |

  @id:operations.container-image.002 @rule:operations.container-image.runs-as-non-root @inferred @source:Dockerfile#USER
  Scenario: The auditor in the image runs as an unprivileged user, not root
    When the operator runs the image without choosing a user
    Then the auditor runs as user ID 10001
    And the auditor has no root privileges inside the container

  @id:operations.container-image.003 @rule:operations.container-image.kubectl-checksum-verified @inferred @source:Dockerfile#fetch
  Scenario: The image ships a pinned kubectl only if it matches its published checksum
    Given the image is built for kubectl version 1.33.2 on the target platform
    When the build fetches kubectl
    Then the build fails if the downloaded kubectl does not match the checksum published beside it
    And the finished image has kubectl on its PATH and it reports its client version
