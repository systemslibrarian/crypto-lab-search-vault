import type { Document } from './types';

/**
 * A small corporate-records corpus — the setting the leakage-abuse literature
 * actually studies (Islam–Kuzu–Kantarcioglu ran on Enron email). The keyword
 * assignments are deliberately structured: clusters overlap, document counts
 * mostly collide, and no two keywords share an identical co-occurrence row.
 * That is what makes the attack exhibit honest — the recovery has to come from
 * the pattern, not from a giveaway.
 */
export const KEYWORDS = [
  'acquisition',
  'audit',
  'bonus',
  'breach',
  'contract',
  'harassment',
  'invoice',
  'layoff',
  'lawsuit',
  'merger',
  'patent',
  'resign',
  'salary',
  'subpoena',
] as const;

export type Keyword = (typeof KEYWORDS)[number];

export const CORPUS: Document[] = [
  {
    id: 'd01',
    title: 'Q3 payroll adjustment memo',
    body: 'Mid-year adjustments applied to bands 4 through 7, effective the first pay period of October.',
    keywords: ['salary', 'bonus'],
  },
  {
    id: 'd02',
    title: 'Notice of unauthorized access to customer records',
    body: 'An unauthorized party reached a replica database on 14 August. Scope and notification duties are under review.',
    keywords: ['breach', 'audit'],
  },
  {
    id: 'd03',
    title: 'Complaint filed in district court',
    body: 'Plaintiff seeks damages and injunctive relief. Service accepted; responsive pleading due in 21 days.',
    keywords: ['lawsuit', 'subpoena'],
  },
  {
    id: 'd04',
    title: 'Board deck — proposed combination with Northwind',
    body: 'Strategic rationale, synergy model, and an indicative range for the exchange ratio.',
    keywords: ['merger', 'acquisition'],
  },
  {
    id: 'd05',
    title: 'Workforce reduction plan, phase one',
    body: 'Role eliminations by function, with notice periods and the associated payroll run-off.',
    keywords: ['layoff', 'salary'],
  },
  {
    id: 'd06',
    title: 'Internal controls review, FY24',
    body: 'Sampling of purchase-to-pay transactions; two exceptions noted in vendor onboarding.',
    keywords: ['audit', 'invoice'],
  },
  {
    id: 'd07',
    title: 'Provisional filing — adaptive index structure',
    body: 'Claims cover an index whose labels are derived per query rather than stored in the clear.',
    keywords: ['patent'],
  },
  {
    id: 'd08',
    title: 'Vendor payment schedule, Q4',
    body: 'Net-45 terms across twelve suppliers, with two disputed line items held pending review.',
    keywords: ['invoice', 'contract'],
  },
  {
    id: 'd09',
    title: 'Master services agreement — Northwind',
    body: 'Term, service levels, and the change-of-control clause that survives the transaction.',
    keywords: ['contract', 'merger'],
  },
  {
    id: 'd10',
    title: 'Exit interview summary — engineering',
    body: 'Departing staff cite compensation banding and limited internal mobility.',
    keywords: ['resign', 'salary'],
  },
  {
    id: 'd11',
    title: 'Retention grant schedule',
    body: 'Cash and equity grants for staff designated critical through the transition window.',
    keywords: ['bonus', 'layoff'],
  },
  {
    id: 'd12',
    title: 'HR investigation report 24-118',
    body: 'Findings on conduct reported in the western region; counsel engaged on 3 June.',
    keywords: ['harassment', 'lawsuit'],
  },
  {
    id: 'd13',
    title: 'Preservation notice — litigation hold',
    body: 'Custodians must suspend deletion of records touching the incident and its aftermath.',
    keywords: ['subpoena', 'lawsuit', 'breach'],
  },
  {
    id: 'd14',
    title: 'Due diligence checklist — target company',
    body: 'Financial, legal, and control-environment items requested before signing.',
    keywords: ['acquisition', 'audit', 'contract'],
  },
  {
    id: 'd15',
    title: 'Post-incident forensics timeline',
    body: 'Reconstructed sequence from first anomalous login through containment, hour by hour.',
    keywords: ['breach', 'subpoena'],
  },
  {
    id: 'd16',
    title: 'Severance terms for affected staff',
    body: 'Standard package by tenure band, with release language and continued benefits.',
    keywords: ['layoff', 'contract', 'salary'],
  },
  {
    id: 'd17',
    title: 'Patent portfolio valuation for the deal',
    body: 'Family-by-family valuation, with encumbrances flagged for the acquirer.',
    keywords: ['patent', 'acquisition', 'merger'],
  },
  {
    id: 'd18',
    title: 'Resignation letter — VP Finance',
    body: 'Two weeks notice, with an unvested award schedule attached for review.',
    keywords: ['resign', 'bonus'],
  },
  {
    id: 'd19',
    title: 'Whistleblower intake — finance team',
    body: 'Anonymous report alleging conduct issues and irregular expense approvals.',
    keywords: ['harassment', 'audit'],
  },
  {
    id: 'd20',
    title: 'Settlement memorandum, sealed',
    body: 'Terms of resolution, mutual releases, and a confidentiality undertaking.',
    keywords: ['lawsuit', 'contract'],
  },
  {
    id: 'd21',
    title: 'Compensation benchmarking study',
    body: 'Market percentiles by role family, with variable pay treated separately.',
    keywords: ['salary', 'bonus', 'audit'],
  },
  {
    id: 'd22',
    title: 'Regulator request for documents',
    body: 'Formal demand covering incident records, control testing, and remediation status.',
    keywords: ['subpoena', 'breach', 'audit'],
  },
  {
    id: 'd23',
    title: 'Integration plan — day one',
    body: 'Reporting lines, redundant functions, and expected voluntary departures.',
    keywords: ['merger', 'layoff', 'resign'],
  },
  {
    id: 'd24',
    title: 'Licensing dispute over prior art',
    body: 'Counterparty asserts a family predating our filing; royalties withheld pending resolution.',
    keywords: ['patent', 'lawsuit', 'invoice'],
  },
];

/** Which documents contain a keyword, in corpus order. */
export function documentsFor(keyword: string, corpus: Document[] = CORPUS): string[] {
  return corpus.filter((d) => d.keywords.includes(keyword)).map((d) => d.id);
}

export function documentById(id: string, corpus: Document[] = CORPUS): Document | undefined {
  return corpus.find((d) => d.id === id);
}
