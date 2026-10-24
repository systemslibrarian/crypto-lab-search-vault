import './styles.css';
import { renderAttack } from './ui/attack-view';
import { renderBuild } from './ui/build';
import { renderChallenge } from './ui/challenge';
import { renderCompare } from './ui/compare';
import { renderConjunctive } from './ui/conjunctive';
import { renderIntro } from './ui/intro';
import { renderLeakage } from './ui/leakage-view';
import { renderPeks } from './ui/peks';
import { renderScope } from './ui/scope';
import { renderSearch } from './ui/search';
import { initState } from './ui/state';
import { ConjunctiveLesson } from './oxt/lesson';

async function main(): Promise<void> {
  const mount = document.getElementById('exhibits');
  if (!mount) throw new Error('#exhibits not found');

  // Build the vault before anything renders: every exhibit displays real
  // values from it, so there is no placeholder state to fake.
  const [, conjunctiveLesson] = await Promise.all([
    initState(),
    ConjunctiveLesson.create(),
  ]);

  mount.append(
    renderIntro(),
    renderBuild(),
    renderSearch(),
    renderLeakage(),
    renderAttack(),
    renderChallenge(),
    renderCompare(),
    renderConjunctive(conjunctiveLesson),
    renderPeks(),
    renderScope(),
  );
}

void main();
