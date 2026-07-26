import type { TemplatePreviewSampleSettings } from '../../api/types';

export type TemplatePreviewSampleUpdate = <Key extends keyof TemplatePreviewSampleSettings>(
  key: Key,
  value: TemplatePreviewSampleSettings[Key],
) => void;

export interface TemplatePreviewSampleSectionProps {
  value: TemplatePreviewSampleSettings;
  canEdit: boolean;
  update: TemplatePreviewSampleUpdate;
}
