/** Server-aligned ceiling for a friendly template-save name. */
export const TEMPLATE_VERSION_NAME_MAX_CODE_POINTS = 200;

export interface NormalizedTemplateVersionName {
  value: string;
  tooLong: boolean;
}

/**
 * Trim and count a version name the same way Rust's `str::chars()` does server-side.
 *
 * JavaScript `string.length` and native input `maxLength` count UTF-16 code units, so astral
 * characters such as emoji count twice there. Iterating the string counts Unicode code points
 * instead and keeps the browser boundary aligned with the API's 200-character rule.
 */
export function normalizeTemplateVersionName(input: string): NormalizedTemplateVersionName {
  const value = input.trim();
  return {
    value,
    tooLong: [...value].length > TEMPLATE_VERSION_NAME_MAX_CODE_POINTS,
  };
}
