@domain:documentation @area:site-theme @from:stylesheets/extra
Feature: A consistent, self-hosted look for the documentation and splash page
  Readers of the rbac-auditor docs and splash page see one recognisable security-branded palette, legible in light and dark schemes, without the site pulling anything from third-party servers.

  Background:
    Given the documentation site and the splash page are published together, the splash at / and the rendered docs at /docs/

  @id:docs.documentation.site-theme.001 @rule:documentation.site-theme.single-shared-palette @inferred @source:docs/stylesheets/extra.css#:root
  Scenario: The splash page and the docs show the same accent colours
    Given the project's accent pair is orange #fb923c and red #ef4444
    When a reader opens the splash page and then the rendered docs
    Then the splash headline and its primary button use an orange-to-red gradient
    And links in the light scheme, primary buttons and the home hero in the docs use the same orange and red
    And changing the accent pair in the docs theme changes both the splash page and the docs

  @id:docs.documentation.site-theme.002 @rule:documentation.site-theme.no-external-assets @inferred @source:docs/stylesheets/extra.css#:root
  Scenario: The documentation loads no fonts or styles from third-party servers
    Given a reader whose browser blocks or cannot reach external hosts
    When the reader opens the rendered docs
    Then body text renders in the operating system's own sans-serif font
    And code renders in the operating system's own monospace font
    And no request is made to a font CDN or web-font service

  @id:docs.documentation.site-theme.003 @rule:documentation.site-theme.legible-in-both-schemes @inferred @source:docs/stylesheets/extra.css#[data-md-color-scheme="slate"]
  Scenario Outline: Links stay readable in both the light and the dark scheme
    Given the docs offer a light scheme and a dark scheme
    When the reader views a page in the <scheme> scheme
    Then the page background is <background>
    And links are shown in <link colour>

    Examples:
      | scheme | background                                   | link colour    |
      | light  | Material's default white                     | red #ef4444    |
      | dark   | near-black #0b0f1a, header and tabs included | orange #fb923c |

  @id:docs.documentation.site-theme.004 @rule:documentation.site-theme.wide-tables-scroll @inferred @source:docs/stylesheets/extra.css#.md-typeset table:not([class]) @questionable
  Scenario: A table wider than the screen is cut off rather than scrollable
    Given a docs page contains a table wider than the reader's screen
    When the reader views the page on a narrow screen
    Then the table is drawn as a rounded card
    And columns beyond the card's right edge are hidden and cannot be scrolled into view

  @id:docs.documentation.site-theme.005 @rule:documentation.site-theme.no-placeholder-logo @inferred @source:docs/stylesheets/extra.css#.md-header__button.md-logo
  Scenario: The docs header shows no stand-in logo while the project has none
    Given the project has not configured a logo for the docs
    When the reader opens any docs page
    Then the header shows the project title without a generic book icon
    And the navigation drawer title shows no generic book icon
