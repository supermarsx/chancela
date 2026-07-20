import { afterEach, describe, expect, it } from 'vitest';
import {
  applyAppearance,
  applyButtonTexture,
  applyColorOverrides,
  applyLocale,
  applyThemeMode,
  applyTextureIntensity,
  isHexColor,
  parseHexColor,
  readableInk,
  relativeLuminance,
} from './appearance';
import type { AppearanceSettings } from '../api/types';

function root(): HTMLElement {
  return document.documentElement;
}

afterEach(() => {
  root().removeAttribute('data-theme');
  root().style.removeProperty('--leather-grain-opacity');
  root().removeAttribute('data-button-texture');
  root().removeAttribute('lang');
  for (const prop of [
    '--accent',
    '--accent-strong',
    '--on-accent',
    '--bg',
    '--surface',
    '--leather-base',
    '--text',
    '--text-muted',
  ]) {
    root().style.removeProperty(prop);
  }
});

describe('applyThemeMode', () => {
  it('stamps data-theme for a forced theme and removes it for system', () => {
    applyThemeMode('dark');
    expect(root().getAttribute('data-theme')).toBe('dark');
    applyThemeMode('light');
    expect(root().getAttribute('data-theme')).toBe('light');
    applyThemeMode('system');
    expect(root().hasAttribute('data-theme')).toBe(false);
  });
});

describe('applyTextureIntensity', () => {
  it('publishes the 0..100 intensity as a 0..1 opacity var, clamped', () => {
    applyTextureIntensity(60);
    expect(root().style.getPropertyValue('--leather-grain-opacity')).toBe('0.6');
    applyTextureIntensity(0);
    expect(root().style.getPropertyValue('--leather-grain-opacity')).toBe('0');
    applyTextureIntensity(100);
    expect(root().style.getPropertyValue('--leather-grain-opacity')).toBe('1');
    applyTextureIntensity(250);
    expect(root().style.getPropertyValue('--leather-grain-opacity')).toBe('1');
  });
});

describe('applyLocale', () => {
  it('reflects the locale onto the document lang', () => {
    applyLocale('en-US');
    expect(root().lang).toBe('en-US');
    applyLocale('pt-PT');
    expect(root().lang).toBe('pt-PT');
  });
});

describe('applyButtonTexture', () => {
  it('stamps the on/off button-texture flag on the root', () => {
    applyButtonTexture(true);
    expect(root().getAttribute('data-button-texture')).toBe('on');
    applyButtonTexture(false);
    expect(root().getAttribute('data-button-texture')).toBe('off');
  });
});

describe('colour helpers', () => {
  it('validates hex colours', () => {
    expect(isHexColor('#abc')).toBe(true);
    expect(isHexColor('#AABBCC')).toBe(true);
    expect(isHexColor('#12g')).toBe(false);
    expect(isHexColor('abc')).toBe(false);
    expect(isHexColor(undefined)).toBe(false);
    expect(isHexColor('#abcd')).toBe(false);
  });

  it('parses shorthand and full hex to rgb', () => {
    expect(parseHexColor('#fff')).toEqual([255, 255, 255]);
    expect(parseHexColor('#000000')).toEqual([0, 0, 0]);
    expect(parseHexColor('#1f6f4a')).toEqual([31, 111, 74]);
    expect(parseHexColor('nope')).toBeNull();
  });

  it('orders luminance dark < light', () => {
    const dark = relativeLuminance('#10241b')!;
    const light = relativeLuminance('#f7f3ea')!;
    expect(dark).toBeLessThan(light);
    expect(relativeLuminance('bad')).toBeNull();
  });

  it('picks a legible ink for a background', () => {
    // Light ground → dark ink; dark ground → light ink.
    expect(readableInk('#ffffff')).toBe('#10241b');
    expect(readableInk('#0b1a13')).toBe('#f7f3ea');
  });
});

describe('applyColorOverrides', () => {
  it('sets custom properties for set fields and derives readable tokens', () => {
    applyColorOverrides({
      primary: '#3355ff',
      secondary: '#aa2244',
      background: '#101010',
      surface: '#202020',
    });
    const style = root().style;
    expect(style.getPropertyValue('--accent-strong')).toBe('#3355ff');
    expect(style.getPropertyValue('--accent')).toBe('#aa2244');
    expect(style.getPropertyValue('--bg')).toBe('#101010');
    expect(style.getPropertyValue('--leather-base')).toBe('#101010');
    expect(style.getPropertyValue('--surface')).toBe('#202020');
    // A dark surface derives a light ink so text stays legible.
    expect(style.getPropertyValue('--text')).toBe('#f7f3ea');
    expect(style.getPropertyValue('--on-accent')).not.toBe('');
    expect(style.getPropertyValue('--text-muted')).toContain('color-mix');
  });

  it('clears properties for unset fields (theme default wins again)', () => {
    applyColorOverrides({ primary: '#3355ff' });
    expect(root().style.getPropertyValue('--accent-strong')).toBe('#3355ff');
    applyColorOverrides({});
    expect(root().style.getPropertyValue('--accent-strong')).toBe('');
    expect(root().style.getPropertyValue('--accent')).toBe('');
    expect(root().style.getPropertyValue('--bg')).toBe('');
    expect(root().style.getPropertyValue('--text')).toBe('');
  });

  it('ignores malformed colours', () => {
    applyColorOverrides({ primary: 'red', background: '#zzz' });
    expect(root().style.getPropertyValue('--accent-strong')).toBe('');
    expect(root().style.getPropertyValue('--bg')).toBe('');
  });
});

describe('applyAppearance', () => {
  it('applies theme, intensity and button texture together', () => {
    const appearance: AppearanceSettings = {
      theme: 'dark',
      leather_texture: true,
      texture_intensity: 25,
      button_texture: false,
    };
    applyAppearance(appearance);
    expect(root().getAttribute('data-theme')).toBe('dark');
    expect(root().style.getPropertyValue('--leather-grain-opacity')).toBe('0.25');
    expect(root().getAttribute('data-button-texture')).toBe('off');
  });
});
