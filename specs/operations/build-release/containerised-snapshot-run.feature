@domain:operations @area:build-release @from:rbac-auditor/makefile
Feature: Snapshotting a cluster through the packaged image
  Lets an operator snapshot the cluster in their own kubeconfig from the container image, without the auditor being able to change that kubeconfig or leave root-owned files behind.

  Background:
    Given the operator has a kubeconfig for the cluster in their home directory

  @id:operations.build-release.001 @rule:operations.image-run.kubeconfig-read-only-and-runs-as-operator @inferred @source:Makefile#run
  Scenario: The containerised run cannot alter the operator's kubeconfig and runs as the operator
    Given no subcommand has been chosen for the run
    When the operator runs the auditor through the packaged image
    Then the image is built first, then the auditor takes a snapshot of the cluster
    And the kubeconfig is available to the auditor read-only
    And the auditor runs with the operator's own user and group, not as root
