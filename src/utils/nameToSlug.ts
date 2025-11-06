export const nameToSlug = (text: string): string => {
  return text.toLowerCase().trim().replace(/\s+/g, '-');
};
