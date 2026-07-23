import { useTemplatesEditorT } from '../../i18n/templatesEditorFallback';
import { Icon, SubNav } from '../../ui';

export type TemplateEditorTab = 'content' | 'properties';
export type UserTemplateEditorTab = TemplateEditorTab | 'versions';

export function TemplateEditorTabs({
  active,
  onSelect,
  showVersions = false,
}: {
  active: UserTemplateEditorTab;
  onSelect: (tab: UserTemplateEditorTab) => void;
  /** Version history is meaningful only for an already-persisted user template. */
  showVersions?: boolean;
}) {
  const bt = useTemplatesEditorT();
  const items = [
    {
      id: 'content' as const,
      label: bt('templates.editor.tabs.content'),
      icon: <Icon.FileText />,
    },
    {
      id: 'properties' as const,
      label: bt('templates.editor.tabs.properties'),
      icon: <Icon.Sliders />,
    },
    ...(showVersions
      ? [
          {
            id: 'versions' as const,
            label: bt('templates.editor.tabs.versions'),
            icon: <Icon.Shuffle />,
          },
        ]
      : []),
  ];
  return (
    <SubNav
      items={items}
      active={active}
      onSelect={onSelect}
      ariaLabel={bt('templates.editor.tabs.aria')}
    />
  );
}
