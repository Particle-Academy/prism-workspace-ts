import { describe, expect, it } from 'vitest';
import { PathGuard, PathRefused, type RefusalCode } from '../src/index.js';

const guard = new PathGuard();
const refused: Array<[string, RefusalCode]> = [
  ['', 'path_is_empty'], ['../secret', 'path_traverses_outside_workspace'],
  ['/etc/passwd', 'path_is_absolute'], ['C:\\secret', 'path_is_absolute'],
  ['\\\\server\\share', 'path_is_unc_or_device_namespace'], ['a\0b', 'path_contains_null_byte'],
  ['a\nb', 'path_contains_control_character'], ['a\u200bb', 'path_contains_invisible_character'],
  ['a\u2215b', 'path_contains_separator_homoglyph'], ['%2e%2e/report', 'path_contains_encoded_separator'],
  ['report:secret', 'path_contains_alternate_data_stream'], ['nul.txt', 'path_is_reserved_device_name'],
  ['draft. ', 'path_has_edge_dot_or_space'], ['draft~1.txt', 'path_uses_short_name_alias'],
  ['~/secret', 'path_uses_home_expansion'], ['..cache/notes', 'path_traverses_outside_workspace'],
];

describe('PathGuard', () => {
  it.each(refused)('refuses %j with %s', (path, code) => {
    try { guard.guard(path); expect.fail('expected refusal'); }
    catch (error) { expect(error).toBeInstanceOf(PathRefused); expect((error as PathRefused).code).toBe(code); }
  });
  it.each([
    ['reports/q1.md', 'reports/q1.md'], ['reports\\q1.md', 'reports/q1.md'],
    ['./reports//q1.md', 'reports/q1.md'], ['50% off.md', '50% off.md'],
  ])('normalizes %j', (input, expected) => expect(guard.guard(input)).toBe(expected));
  it('keeps the reference order for overlapping failures', () => {
    try { guard.guard('\ud800'.repeat(400)); expect.fail('expected refusal'); }
    catch (error) { expect((error as PathRefused).code).toBe('path_too_long'); }
  });
});
