import sys
from pathlib import Path
from backend.core.detector import ProjectDetector
from backend.analysis.facts_builder import FactsBuilder

def debug():
    fixture_root = Path("g:/Best-Practices-Doctor/backend/tests/fixtures/sample-lara").resolve()
    print(f"Fixture Root: {fixture_root}")
    
    # 1. Detection
    detector = ProjectDetector(str(fixture_root))
    info = detector.detect()
    print(f"Project Type: {info.project_type}")
    
    # 2. Extract Facts
    builder = FactsBuilder(info)
    # Patch builder to be even more verbose
    def verbose_find(pattern):
        import os
        print(f"Searching for {pattern}...")
        for root, dirs, files in os.walk(fixture_root):
            for f in files:
                if f.endswith(pattern.replace("**/*", "").replace("*", "")):
                    print(f"  Found file: {f}")
                    yield Path(root) / f
                    
    builder._find_files = verbose_find
    
    facts = builder.build()
    print(f"Found {len(facts.classes)} classes")
    for c in facts.classes:
        print(f"  Class: {c.fqcn}")
    
    if len(facts.classes) == 0:
        # Debug parsing manually
        test_file = fixture_root / "app/Http/Controllers/UserController.php"
        if test_file.exists():
            print(f"Parsing {test_file} manually...")
            content = test_file.read_text()
            import tree_sitter
            import tree_sitter_php
            lang = tree_sitter.Language(tree_sitter_php.language_php())
            parser = tree_sitter.Parser(lang)
            tree = parser.parse(content.encode("utf8"))
            print(f"Root Node Type: {tree.root_node.type}")
            
            query = tree_sitter.Query(lang, """
                (class_declaration 
                    name: (name) @class_name
                )
            """)
            cursor = tree_sitter.QueryCursor(query)
            caps = cursor.captures(tree.root_node)
            print(f"Captures Type: {type(caps)}")
            print(f"Captures: {caps}")

if __name__ == "__main__":
    debug()
