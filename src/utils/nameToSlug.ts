export const nameToSlug = (text: string): string => {
  return text
    .toLowerCase()
    .trim()
    .replace(/(\s|[^a-z0-9-_])+/g, '-');
};
