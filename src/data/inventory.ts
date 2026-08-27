import type { Asset } from '../domain/types';

// Every name, owner, service, and version below is synthetic demonstration data.
export const inventory: Asset[] = [
  {
    id: 'AST-001', hostname: 'perimeter-fw-01', service: 'Customer edge', owner: 'Network Defense',
    environment: 'production', internetFacing: true, criticality: 5,
    software: [{ productId: 'paloalto:pan-os', name: 'PAN-OS', version: '10.2.8' }],
  },
  {
    id: 'AST-002', hostname: 'commerce-adc-01', service: 'Commerce gateway', owner: 'Platform Edge',
    environment: 'production', internetFacing: true, criticality: 5,
    software: [{ productId: 'citrix:netscaler-adc', name: 'NetScaler ADC', version: '13.1-49.13' }],
  },
  {
    id: 'AST-003', hostname: 'partner-files-01', service: 'Partner file exchange', owner: 'B2B Operations',
    environment: 'production', internetFacing: true, criticality: 5,
    software: [{ productId: 'progress:moveit-transfer', name: 'MOVEit Transfer', version: '2023.0.2' }],
  },
  {
    id: 'AST-004', hostname: 'remote-ops-01', service: 'Remote support', owner: 'Service Operations',
    environment: 'production', internetFacing: true, criticality: 4,
    software: [{ productId: 'connectwise:screenconnect', name: 'ScreenConnect', version: '23.9.7' }],
  },
  {
    id: 'AST-005', hostname: 'build-teamcity-01', service: 'Release automation', owner: 'Developer Platform',
    environment: 'development', internetFacing: false, criticality: 4,
    software: [{ productId: 'jetbrains:teamcity', name: 'TeamCity', version: '2023.11.3' }],
  },
  {
    id: 'AST-006', hostname: 'knowledge-confluence-01', service: 'Engineering knowledge', owner: 'Workplace Apps',
    environment: 'corporate', internetFacing: false, criticality: 3,
    software: [{ productId: 'atlassian:confluence', name: 'Confluence Data Center', version: '8.3.2' }],
  },
  {
    id: 'AST-007', hostname: 'storefront-web-01', service: 'Digital storefront', owner: 'Commerce SRE',
    environment: 'production', internetFacing: true, criticality: 5,
    software: [
      { productId: 'php:php-cgi', name: 'PHP CGI', version: '8.1.25' },
      { productId: 'nginx:nginx', name: 'NGINX', version: '1.24.0' },
    ],
  },
  {
    id: 'AST-008', hostname: 'workforce-vpn-01', service: 'Workforce access', owner: 'Identity & Access',
    environment: 'production', internetFacing: true, criticality: 5,
    software: [{ productId: 'ivanti:connect-secure', name: 'Ivanti Connect Secure', version: '22.5R2.3' }],
  },
  {
    id: 'AST-009', hostname: 'branch-core-01', service: 'Branch connectivity', owner: 'Network Engineering',
    environment: 'production', internetFacing: true, criticality: 4,
    software: [{ productId: 'cisco:ios-xe', name: 'Cisco IOS XE', version: '17.9.3' }],
  },
  {
    id: 'AST-010', hostname: 'checkout-api-01', service: 'Checkout API', owner: 'Payments SRE',
    environment: 'production', internetFacing: true, criticality: 5,
    software: [{ productId: 'apache:log4j-core', name: 'Apache Log4j Core', version: '2.14.1' }],
  },
  {
    id: 'AST-011', hostname: 'bastion-01', service: 'Privileged access', owner: 'Cloud Security',
    environment: 'production', internetFacing: true, criticality: 4,
    software: [{ productId: 'openssh:openssh', name: 'OpenSSH', version: '9.2p1' }],
  },
  {
    id: 'AST-012', hostname: 'release-builder-01', service: 'Artifact build', owner: 'Developer Platform',
    environment: 'development', internetFacing: false, criticality: 3,
    software: [{ productId: 'tukaani:xz-utils', name: 'XZ Utils', version: '5.6.1' }],
  },
  {
    id: 'AST-013', hostname: 'windows-endpoint-pool', service: 'Corporate endpoints', owner: 'Endpoint Engineering',
    environment: 'corporate', internetFacing: false, criticality: 3, instanceCount: 300,
    software: [{ productId: 'microsoft:windows-smartscreen', name: 'Windows SmartScreen', version: '11-23H2' }],
  },
  {
    id: 'AST-014', hostname: 'analytics-node-01', service: 'Behavior analytics', owner: 'Data Platform',
    environment: 'production', internetFacing: false, criticality: 2,
    software: [{ productId: 'linux:kernel', name: 'Linux kernel', version: '6.1.0' }],
  },
  {
    id: 'AST-015', hostname: 'hr-db-01', service: 'People data', owner: 'Business Systems',
    environment: 'production', internetFacing: false, criticality: 5,
    software: [{ productId: 'postgresql:postgresql', name: 'PostgreSQL', version: '16.3' }],
  },
];
