from pathlib import Path

from analysis.facts_builder import FactsBuilder
from schemas.project_type import ProjectInfo


def test_treesitter_parses_tsx_typed_export_const_component(tmp_path: Path):
    # This TSX pattern intentionally does NOT match the regex fallback parser:
    # "export const Name: React.FC<Props> = ..."
    # So if this passes, it strongly indicates Tree-sitter TSX is working.
    page = tmp_path / "resources" / "js" / "Pages" / "TypedPage.tsx"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(
        """import React from "react";

type Props = { id: number };

export const TypedPage: React.FC<Props> = (props) => {
  return <div>{props.id}</div>;
};
""",
        encoding="utf-8",
    )

    facts = FactsBuilder(ProjectInfo(root_path=str(tmp_path))).build()

    names = [c.name for c in facts.react_components if c.file_path.endswith("TypedPage.tsx")]
    assert "TypedPage" in names

