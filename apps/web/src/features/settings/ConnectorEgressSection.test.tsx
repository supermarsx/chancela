import { describe, expect, it } from 'vitest';

import { entryProblem, parseAllowedHosts } from './ConnectorEgressSection';

describe('connector egress allowlist entry validation', () => {
  it('rejects the entries that would make connector egress an exfiltration primitive', () => {
    // The cloud instance-metadata endpoint and the link-local range that carries it.
    expect(entryProblem('169.254.169.254')).toBe('metadata');
    expect(entryProblem('169.254.0.0/16')).toBe('metadata');
    expect(entryProblem('fe80::1')).toBe('metadata');
    // Pointing a connector back at the host running Chancela.
    expect(entryProblem('localhost')).toBe('loopback');
    expect(entryProblem('api.localhost')).toBe('loopback');
    expect(entryProblem('127.0.0.1')).toBe('loopback');
    expect(entryProblem('::1')).toBe('loopback');
    // Never a legitimate target.
    expect(entryProblem('0.0.0.0')).toBe('forbiddenRange');
    expect(entryProblem('224.0.0.1')).toBe('forbiddenRange');
    expect(entryProblem('::')).toBe('forbiddenRange');
  });

  it('rejects wildcards outright rather than bounding them', () => {
    for (const entry of ['*', '*.example.com', 'example.*', 'ex*mple.com']) {
      expect(entryProblem(entry), entry).toBe('wildcard');
    }
  });

  it('rejects anything that is not a bare hostname or IP/CIDR', () => {
    for (const entry of [
      '',
      'https://backup.example.com',
      'backup.example.com:443',
      'backup.example.com/path',
      'user@backup.example.com',
      'backup.example.com?x=1',
      '[2001:db8::1]',
      'a.example.com,b.example.com',
      'back up.example.com',
      'backup.example.com/33',
      '10.0.0.0/64',
    ]) {
      expect(entryProblem(entry), entry).toBe('format');
    }
  });

  it('bounds how broad a CIDR an administrator may open', () => {
    expect(entryProblem('10.0.0.0/8')).toBe('broadPrefix');
    expect(entryProblem('2001:db8::/16')).toBe('broadPrefix');
    expect(entryProblem('10.42.0.0/16')).toBeNull();
    expect(entryProblem('2001:db8:1234::/48')).toBeNull();
  });

  it('accepts ordinary hosts and literals', () => {
    for (const entry of [
      'backup.example.com',
      'BACKUP.example.com',
      'nas.internal',
      '10.42.8.15',
      '192.168.1.0/24',
    ]) {
      expect(entryProblem(entry), entry).toBeNull();
    }
  });

  it('normalises the textarea into trimmed, lowercased, duplicate-free entries', () => {
    expect(
      parseAllowedHosts('  Backup.Example.com \n\n10.42.0.0/16\nbackup.example.com\n'),
    ).toEqual(['backup.example.com', '10.42.0.0/16']);
    expect(parseAllowedHosts('   \n \n')).toEqual([]);
  });
});
