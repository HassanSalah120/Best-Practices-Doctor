from analysis.facts_builder import FactsBuilder
from core.detector import ProjectDetector
from schemas.project_type import ProjectInfo


def test_facts_builder_registers_composer_and_package_files_for_regex_rules(fixture_path):
    laravel_root = fixture_path / "sample-lara"
    inertia_root = fixture_path / "laravel-inertia-react-mini"

    laravel_facts = FactsBuilder(ProjectDetector(str(laravel_root)).detect()).build()
    inertia_facts = FactsBuilder(ProjectDetector(str(inertia_root)).detect()).build()

    assert "composer.json" in laravel_facts.files
    assert "composer.json" in inertia_facts.files
    assert "package.json" in inertia_facts.files


def test_facts_builder_ignores_compiled_public_dist_assets(tmp_path):
    source = tmp_path / "frontend" / "src"
    source.mkdir(parents=True)
    (source / "App.tsx").write_text("export function App() { return <main>Hello</main>; }", encoding="utf-8")

    assets = tmp_path / "public" / "dist" / "assets"
    assets.mkdir(parents=True)
    (assets / "App-compiled.js").write_text("localStorage.setItem('access_token', token);", encoding="utf-8")

    facts = FactsBuilder(ProjectInfo(root_path=str(tmp_path))).build()

    assert "frontend/src/App.tsx" in facts.files
    assert not any(path.startswith("public/dist/assets/") for path in facts.files)
