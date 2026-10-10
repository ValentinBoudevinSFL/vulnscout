from uuid import uuid4

from src.helpers.spdx_sources import SPDXSources


def test_source_graph_is_cycle_safe_and_scan_scoped():
    sources = SPDXSources()
    scan = uuid4()
    source, recipe, binary = ("ns", "source"), ("ns", "recipe"), ("ns", "binary")
    url = f"git+https://example.org/lib@{'a' * 40}"
    sources.record(scan, {binary: "lib@1"}, {source: url}, {(binary, recipe), (recipe, binary)},
                   {(recipe, source)})
    sources.record(uuid4(), {binary: "other@1"}, {}, {(binary, recipe)}, {(recipe, source)})
    assert sources.resolve() == {"lib@1": {url}, "other@1": set()}
