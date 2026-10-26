/** Public teaching fixture. Plaintext appears only in the narrator/oracle. */
export const MUSE_SCENARIO = {
  writers: [
    { id: 'writer-a', label: 'Clinical A', keywords: ['audit', 'budget'] },
    { id: 'writer-b', label: 'Legal B', keywords: ['audit', 'lawsuit'] },
    { id: 'writer-c', label: 'Security C', keywords: ['breach', 'forensic'] },
  ],
  readers: [
    { id: 'reader-known', label: 'Known-query reader' },
    { id: 'reader-target', label: 'Target reader' },
    { id: 'reader-outsider', label: 'Unauthorized reader' },
  ],
  authorizations: {
    'reader-known': ['writer-a'],
    'reader-target': ['writer-a', 'writer-b', 'writer-c'],
    'reader-outsider': [],
  },
} as const;
