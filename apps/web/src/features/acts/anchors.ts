export const ACT_CONVENING_GUIDANCE_ID = 'convening-guidance';
export const ACT_CONVENING_GUIDANCE_HASH = `#${ACT_CONVENING_GUIDANCE_ID}`;

export function actConveningGuidanceRoute(actRoute: string | undefined): string | undefined {
  const route = actRoute?.trim();
  if (!route) return undefined;

  const url = new URL(route, 'http://chancela.local');
  if (url.pathname !== '/atas' && !url.pathname.startsWith('/atas/')) return undefined;

  url.hash = ACT_CONVENING_GUIDANCE_HASH;
  return `${url.pathname}${url.search}${url.hash}`;
}
