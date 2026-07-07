import { afterEach, describe, expect, it } from 'vitest';
import {
  applyAppearance,
  applyButtonTexture,
  applyLocale,
  applyThemeMode,
  applyTextureIntensity,
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
