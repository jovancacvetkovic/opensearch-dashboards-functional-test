/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import _ from 'lodash';
import sample_windows_index_settings from '../../../fixtures/plugins/security-analytics-dashboards-plugin/sample_windows_index_settings.json';
import sample_dns_index_settings from '../../../fixtures/plugins/security-analytics-dashboards-plugin/sample_dns_index_settings.json';

import dns_name_rule_data from '../../../fixtures/plugins/security-analytics-dashboards-plugin/integration_tests/rule/create_dns_rule_with_name_selection.json';
import dns_type_rule_data from '../../../fixtures/plugins/security-analytics-dashboards-plugin/integration_tests/rule/create_dns_rule_with_type_selection.json';
import dns_mapping_fields from '../../../fixtures/plugins/security-analytics-dashboards-plugin/integration_tests/rule/sample_dns_field_mappings.json';

import { BACKEND_BASE_PATH } from '../../../utils/base_constants';
import {
  NODE_API,
  OPENSEARCH_DASHBOARDS_URL,
} from '../../../utils/plugins/security-analytics-dashboards-plugin/constants';

const getMappingFields = (properties, items = [], prefix = '') => {
  for (let field in properties) {
    const fullFieldName = prefix ? `${prefix}.${field}` : field;
    const nextProperties = properties[field].properties;
    if (!nextProperties) {
      items.push({
        ruleFieldName: fullFieldName,
        logFieldName: properties[field].path,
      });
    } else {
      getMappingFields(nextProperties, items, fullFieldName);
    }
  }
  return items;
};

const cypressIndexDns = 'cypress-index-dns';
const cypressIndexWindows = 'cypress-index-windows';
const detectorName = 'test detector';
const cypressDNSRule = dns_name_rule_data.title;

const getNameField = () =>
  cy.getInputByPlaceholder('Enter a name for the detector.');

const getNextButton = () => cy.getButtonByText('Next');

const getCreateDetectorButton = () => cy.getButtonByText('Create detector');

const selectDnsLogType = () =>
  cy.getRadioButtonById('dns').click({ force: true });

const validateAlertPanel = (alertName) =>
  cy
    .getElementByText('.euiTitle', 'Alert triggers')
    .parentsUntil('.euiPanel')
    .siblings()
    .eq(2)
    .within(() => cy.getElementByText('button', alertName));

const dataSourceLabel = 'Select or input source indexes or index patterns';

const getDataSourceField = () => cy.getFieldByLabel(dataSourceLabel);

const openDetectorDetails = (detectorName) => {
  cy.getInputByPlaceholder('Search threat detectors')
    .type(`${detectorName}`)
    .pressEnterKey();
  cy.getElementByText('.euiTableCellContent button', detectorName).click();
};

const validateFieldMappingsTable = (message = '') => {
  cy.wait('@getMappingsView').then((interception) => {
    cy.wait(10000).then(() => {
      cy.get('.reviewFieldMappings').should('be.visible');
      const properties = interception.response.body.response.properties;
      const unmapped_field_aliases =
        interception.response.body.response.unmapped_field_aliases.map(
          (field) => [field]
        );

      Cypress.log({
        message: `Validate table data - ${message}`,
      });
      if (_.isEmpty(properties)) {
        validatePendingFieldMappingsPanel(unmapped_field_aliases);
      } else {
        let items = getMappingFields(properties, [], '');
        items = items.map((item) => [item.ruleFieldName, item.logFieldName]);
        validateAutomaticFieldMappingsPanel(items);
      }
    });
  });
};

const editDetectorDetails = (detectorName, panelTitle) => {
  cy.urlShouldContain('detector-details').then(() => {
    cy.getElementByText('.euiTitle', detectorName);
    cy.getElementByText('.euiPanel .euiTitle', panelTitle);
    cy.getElementByText('.euiPanel .euiTitle', panelTitle)
      .parent()
      .siblings()
      .within(() => cy.get('button').contains('Edit').click());
  });
};

const validateAutomaticFieldMappingsPanel = (mappings) =>
  cy.get('.editFieldMappings').within(() => {
    cy.get('.euiAccordion__triggerWrapper button').then(($btn) => {
      cy.get($btn).contains(`Automatically mapped fields (${mappings.length})`);

      // first check if the accordion is expanded, if not than expand the accordion
      if ($btn[0].getAttribute('aria-expanded') === 'false') {
        cy.get($btn[0])
          .click()
          .then(() => {
            cy.getElementByTestSubject('auto-mapped-fields-table')
              .find('.euiBasicTable')
              .validateTable(mappings);
          });
      }
    });
  });

const validatePendingFieldMappingsPanel = (mappings) => {
  cy.get('.editFieldMappings').within(() => {
    // Pending field mappings
    cy.getElementByText('.euiTitle', 'Pending field mappings')
      .parents('.euiPanel')
      .within(() => {
        cy.getElementByTestSubject('pending-mapped-fields-table')
          .find('.euiBasicTable')
          .validateTable(mappings);
      });
  });
};

const createDetector = (detectorName, dataSource, expectFailure) => {
  getCreateDetectorButton().click({ force: true });

  // TEST DETAILS PAGE
  getNameField().type(detectorName);
  getDataSourceField().type(dataSource).type('{enter}');

  selectDnsLogType();

  cy.getElementByText('.euiAccordion .euiTitle', 'Detection rules')
    .click({ force: true, timeout: 5000 })
    .then(() => cy.contains('.euiTable .euiTableRow', 'Dns'));

  cy.getElementByText(
    '.euiAccordion .euiTitle',
    'Configure field mapping - optional'
  );

  cy.get('[aria-controls="mappedTitleFieldsAccordion"]').then(($btn) => {
    // first check if the accordion is expanded, if not than expand the accordion
    if ($btn && $btn[0] && $btn[0].getAttribute('aria-expanded') === 'false') {
      $btn[0].click();
    }
  });

  // go to the alerts page
  getNextButton().click({ force: true });

  // TEST ALERTS PAGE
  cy.getElementByText('.euiTitle.euiTitle--medium', 'Set up alert triggers');
  cy.getInputByPlaceholder('Enter a name to describe the alert condition').type(
    'test_trigger'
  );
  cy.getElementByTestSubject('alert-tags-combo-box')
    .type(`attack.defense_evasion{enter}`)
    .find('input')
    .focus()
    .blur();

  cy.getFieldByLabel('Specify alert severity').selectComboboxItem(
    '1 (Highest)'
  );

  // go to review page
  getNextButton().click({ force: true });

  if (!expectFailure) {
    // TEST REVIEW AND CREATE PAGE
    cy.getElementByText('.euiTitle', 'Review and create');
    cy.getElementByText('.euiTitle', 'Detector details');
    cy.getElementByText('.euiTitle', 'Field mapping');
    cy.getElementByText('.euiTitle', 'Alert triggers');

    cy.validateDetailsItem('Detector name', detectorName);
    cy.validateDetailsItem('Description', '-');
    cy.validateDetailsItem('Detector schedule', 'Every 1 minute');
    cy.validateDetailsItem('Detection rules', '14');
    cy.validateDetailsItem('Created at', '-');
    cy.validateDetailsItem('Last updated time', '-');
    cy.validateDetailsItem(
      'Detector dashboard',
      'Not available for this log type'
    );

    let fields = [];
    for (let field in dns_mapping_fields) {
      fields.push([field, dns_mapping_fields[field]]);
    }
    cy.getElementByText('.euiTitle', 'Field mapping')
      .parentsUntil('.euiPanel')
      .siblings()
      .eq(2)
      .validateTable(fields);
  }

  validateAlertPanel('test_trigger');

  cy.intercept({
    pathname: `${NODE_API.MAPPINGS_BASE}`,
  }).as('createMappingsRequest');
  cy.intercept({
    pathname: `${NODE_API.DETECTORS_BASE}`,
  }).as('createDetectorRequest');

  // create the detector
  cy.getButtonByText('Create').click({ force: true });

  if (!expectFailure) {
    // TEST DETECTOR DETAILS PAGE
    cy.wait('@createMappingsRequest');

    cy.wait('@createDetectorRequest').then((interceptor) => {
      const detectorId = interceptor.response.body.response._id;

      cy.url()
        .should('contain', detectorId)
        .then(() => {
          cy.getElementByText(
            '.euiCallOut',
            `Detector created successfully: ${detectorName}`
          );

          // Confirm detector state
          cy.getElementByText('.euiTitle', detectorName);
          cy.getElementByText('.euiHealth', 'Active').then(() => {
            cy.validateDetailsItem('Detector name', detectorName);
            cy.validateDetailsItem('Description', '-');
            cy.validateDetailsItem('Detector schedule', 'Every 1 minute');
            cy.validateDetailsItem('Detection rules', '14');
            cy.validateDetailsItem(
              'Detector dashboard',
              'Not available for this log type'
            );

            cy.wait(5000); // waiting for the page to be reloaded after pushing detector id into route
            cy.getElementByText('button.euiTab', 'Alert triggers')
              .should('be.visible')
              .click();
            validateAlertPanel('test_trigger');

            cy.intercept({
              pathname: `${NODE_API.MAPPINGS_BASE}`,
            }).as('getMappingFields');

            cy.getElementByText('button.euiTab', 'Field mappings')
              .should('be.visible')
              .click();

            let fields = [];
            for (let field in dns_mapping_fields) {
              fields.push([field, dns_mapping_fields[field]]);
            }
            cy.wait('@getMappingFields');
            cy.wait(2000);
            cy.getElementByText('.euiTitle', 'Field mapping')
              .parentsUntil('.euiPanel')
              .siblings()
              .eq(2)
              .validateTable(fields);
          });
        });
    });
  }
};

describe('Detectors', () => {
  before(() => {
    cy.cleanUpTests();

    cy.createIndex(cypressIndexWindows, null, sample_windows_index_settings);

    // Create test index
    cy.createIndex(cypressIndexDns, null, sample_dns_index_settings).then(() =>
      cy
        .request({
          method: 'POST',
          url: `${BACKEND_BASE_PATH}${NODE_API.RULES_BASE}/_search?pre_packaged=true`,
          headers: {
            'osd-xsrf': true,
          },
          body: {
            from: 0,
            size: 5000,
            query: {
              nested: {
                path: 'rule',
                query: {
                  bool: { must: [{ match: { 'rule.category': 'dns' } }] },
                },
              },
            },
          },
        })
        .should('have.property', 'status', 200)
    );

    cy.createRule(dns_name_rule_data);
    cy.createRule(dns_type_rule_data);
  });

  beforeEach(() => {
    cy.intercept(NODE_API.SEARCH_DETECTORS).as('detectorsSearch');

    // Visit Detectors page
    cy.visit(`${OPENSEARCH_DASHBOARDS_URL}/detectors`);
    cy.wait('@detectorsSearch').should('have.property', 'state', 'Complete');

    // Check that correct page is showing
    cy.contains('Threat detectors');
  });

  it('...should validate form', () => {
    getCreateDetectorButton().click({ force: true });

    getNextButton().should('be.disabled');

    getNameField().should('be.empty');
    getNameField().type('text').focus().blur();

    getNameField()
      .parentsUntil('.euiFormRow__fieldWrapper')
      .siblings()
      .contains(
        'Name should only consist of upper and lowercase letters, numbers 0-9, hyphens, spaces, and underscores. Use between 5 and 50 characters.'
      );

    getNameField()
      .type(' and more text')
      .focus()
      .blur()
      .parentsUntil('.euiFormRow__fieldWrapper')
      .siblings()
      .should('not.exist');
    getNextButton().should('be.disabled');

    getDataSourceField()
      .focus()
      .blur()
      .parentsUntil('.euiFormRow__fieldWrapper')
      .siblings()
      .contains('Select an input source');
    getNextButton().should('be.disabled');

    getDataSourceField().selectComboboxItem(cypressIndexDns);
    getDataSourceField()
      .focus()
      .blur()
      .parentsUntil('.euiFormRow__fieldWrapper')
      .find('.euiFormErrorText')
      .should('not.exist');
    getNextButton().should('not.be.disabled');
  });

  it('...should show mappings warning', () => {
    getCreateDetectorButton().click({ force: true });

    getDataSourceField().type(cypressIndexDns).type('{enter}');

    selectDnsLogType();

    getDataSourceField().type(cypressIndexWindows).type('{enter}');
    getDataSourceField().focus().blur();

    cy.get('.euiCallOut')
      .should('be.visible')
      .contains(
        'To avoid issues with field mappings, we recommend creating separate detectors for different log types.'
      );
  });

  it('...can fail creation', () => {
    createDetector(`${detectorName}_fail`, '.kibana_1', true);
    cy.getElementByText('.euiCallOut', 'Create detector failed.');
  });

  it('...can be created', () => {
    createDetector(detectorName, cypressIndexDns, false);
    cy.contains('Detector created successfully');
  });

  it('...basic details can be edited', () => {
    cy.intercept({
      pathname: `${NODE_API.INDICES_BASE}`,
    }).as('getIndices');
    openDetectorDetails(detectorName);

    editDetectorDetails(detectorName, 'Detector details');

    cy.urlShouldContain('edit-detector-details').then(() => {
      cy.getElementByText('.euiTitle', 'Edit detector details');
    });

    cy.wait('@getIndices');
    getNameField().type('{selectall}{backspace}').type('test detector edited');
    cy.getTextareaByLabel('Description - optional').type('Edited description');

    getDataSourceField().clearCombobox();
    getDataSourceField().selectComboboxItem(cypressIndexWindows);

    cy.getFieldByLabel('Run every').type('{selectall}{backspace}').type('10');
    cy.getFieldByLabel('Run every', 'select').select('Hours');

    cy.getElementByText('button', 'Save changes').click({ force: true });

    cy.urlShouldContain('detector-details').then(() => {
      cy.validateDetailsItem('Detector name', 'test detector edited');
      cy.validateDetailsItem('Description', 'Edited description');
      cy.validateDetailsItem('Detector schedule', 'Every 10 hours');
      cy.validateDetailsItem('Data source', cypressIndexWindows);
    });
  });

  it('...rules can be edited', () => {
    openDetectorDetails(detectorName);

    editDetectorDetails(detectorName, 'Active rules');
    cy.getElementByText('.euiTitle', 'Detection rules (14)');

    cy.getInputByPlaceholder('Search...')
      .type(`${cypressDNSRule}`)
      .pressEnterKey();

    cy.getElementByText('.euiTableCellContent button', cypressDNSRule)
      .parents('td')
      .prev()
      .find('.euiTableCellContent button')
      .click();

    cy.getElementByText('.euiTitle', 'Detection rules (13)');
    cy.getElementByText('button', 'Save changes').click({ force: true });
    cy.urlShouldContain('detector-details').then(() => {
      cy.getElementByText('.euiTitle', detectorName);
      cy.getElementByText('.euiPanel .euiTitle', 'Active rules (13)');
    });
  });

  it('...should update field mappings if data source is changed', () => {
    cy.intercept({
      pathname: `${NODE_API.INDICES_BASE}`,
    }).as('getIndices');
    openDetectorDetails(detectorName);

    editDetectorDetails(detectorName, 'Detector details');

    cy.urlShouldContain('edit-detector-details').then(() => {
      cy.getElementByText('.euiTitle', 'Edit detector details');
    });

    cy.wait('@getIndices');
    cy.get('.reviewFieldMappings').should('not.exist');

    cy.intercept({
      pathname: `${NODE_API.MAPPINGS_VIEW}`,
    }).as('getMappingsView');
    getDataSourceField().clearCombobox();
    getDataSourceField().type(cypressIndexDns).type('{enter}');

    validateFieldMappingsTable('data source is changed');
    cy.getElementByText('button', 'Save changes').click({ force: true });
  });

  it('...should update field mappings if rule selection is changed', () => {
    cy.intercept({
      pathname: `${NODE_API.MAPPINGS_VIEW}`,
    }).as('getMappingsView');

    openDetectorDetails(detectorName);

    editDetectorDetails(detectorName, 'Active rules');

    cy.urlShouldContain('edit-detector-rules').then(() => {
      cy.getElementByText('.euiTitle', 'Edit detector rules');
    });

    cy.get('.reviewFieldMappings').should('not.exist');

    cy.wait('@detectorsSearch');

    // Toggle single search result to unchecked
    cy.get(
      '[data-test-subj="edit-detector-rules-table"] table thead tr:first th:first button'
    ).click({ force: true });

    validateFieldMappingsTable('rules are changed');
  });

  it('...can be deleted', () => {
    cy.intercept({
      pathname: `${NODE_API.RULES_SEARCH}`,
    }).as('getRules');
    openDetectorDetails(detectorName);

    cy.wait('@detectorsSearch');
    cy.wait('@getRules');
    cy.wait('@getRules');

    cy.getButtonByText('Actions')
      .click({ force: true })
      .then(() => {
        cy.intercept({
          pathname: NODE_API.SEARCH_DETECTORS,
        }).as('detectors');
        cy.getElementByText('.euiContextMenuItem', 'Delete').click({
          force: true,
        });
        cy.wait('@detectors').then(() => {
          cy.contains('There are no existing detectors');
        });
      });
  });

  after(() => cy.cleanUpTests());
});
