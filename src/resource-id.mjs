export const RESOURCE_IDS = Object.freeze({
  notes: 'notes',
  instructorNotices: 'instructor_notices',
});

export function resourceIdForPath(pathname) {
  if (typeof pathname !== 'string') return null;
  if (pathname === '/api/notes' || pathname.startsWith('/api/notes/')) {
    return RESOURCE_IDS.notes;
  }
  if (pathname === '/api/instructor-notices'
      || pathname.startsWith('/api/instructor-notices/')) {
    return RESOURCE_IDS.instructorNotices;
  }
  return null;
}
