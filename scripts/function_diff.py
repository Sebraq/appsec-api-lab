"""Diff unificado de funciones concretas entre vulnerable/ y secure/.
Uso: python scripts/function_diff.py get_note search_notes"""
import ast
import difflib
import pathlib
import sys


def source_of(path, name):
    text = pathlib.Path(path).read_text()
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            return text.splitlines(keepends=True)[start - 1 : node.end_lineno]
    return []


for fn in sys.argv[1:]:
    a = source_of("vulnerable/app/main.py", fn)
    b = source_of("secure/app/main.py", fn)
    sys.stdout.writelines(difflib.unified_diff(a, b, f"vulnerable/app/main.py::{fn}", f"secure/app/main.py::{fn}"))
    print()
