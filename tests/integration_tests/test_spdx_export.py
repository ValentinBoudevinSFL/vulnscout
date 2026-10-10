# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.spdx import SPDX
from src.models.package import Package
from src.controllers import ControllersCache
import json
from xml.etree import ElementTree


@pytest.fixture
def spdx_parser():
    return SPDX(ControllersCache())


def test_export_empty_json(spdx_parser):
    output = json.loads(spdx_parser.output_as_json(True, "MY_AUTHOR_NAME"))
    try:
        assert {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
        }.items() <= output.items()
        assert output["documentNamespace"].startswith("https://")
        assert len(output["name"]) > 5
        assert len(output["creationInfo"]["creators"]) == 2
        assert any(map(lambda x: "MY_AUTHOR_NAME" in x, output["creationInfo"]["creators"]))
        assert "packages" not in output or len(output["packages"]) == 0
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


def test_export_uses_generated_namespace_when_document_url_is_blank(monkeypatch, spdx_parser):
    monkeypatch.setenv("DOCUMENT_URL", "")

    json_output = json.loads(spdx_parser.output_as_json(True, "MY_AUTHOR_NAME"))
    assert json_output["documentNamespace"].startswith("https://spdx.org/spdxdocs/")

    xml_output = spdx_parser.output_as_xml(True, "MY_AUTHOR_NAME")
    assert ElementTree.fromstring(xml_output).tag == "Document"


def test_export_components_json(spdx_parser):
    pkg = Package("binutils", "2.38", [], [])
    pkg.add_purl("pkg:generic/gnu/binutils@2.38")
    pkg.add_cpe("cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*")
    spdx_parser.packagesCtrl.add(pkg)
    opsys = Package("linux", "6.8.0-40-generic", ["cpe:2.3:o:*:linux:6.8.0-40-generic:*:*:*:*:*:*:*"], [])
    spdx_parser.packagesCtrl.add(opsys)
    hw = Package("xyz", "rev2.3", ["cpe:2.3:h:*:xyz:rev2.3:*:*:*:*:*:*:*"], [])
    spdx_parser.packagesCtrl.add(hw)
    output = json.loads(spdx_parser.output_as_json())

    try:
        assert {
            "primaryPackagePurpose": "APPLICATION",
            "name": "binutils",
            "versionInfo": "2.38",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][0].items()
        assert {
            "primaryPackagePurpose": "OPERATING-SYSTEM",
            "name": "linux",
            "versionInfo": "6.8.0-40-generic",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][1].items()
        assert {
            "primaryPackagePurpose": "DEVICE",
            "name": "xyz",
            "versionInfo": "rev2.3",
            "filesAnalyzed": False,
            "downloadLocation": "NOASSERTION"
        }.items() <= output["packages"][2].items()

        assert len(output["packages"]) == 3
    except Exception as e:
        print(json.dumps(output, indent=2))
        raise e


@pytest.mark.parametrize("fast", [False, True])
def test_spdx2_export_roundtrips_all_source_revisions(spdx_parser, fast):
    from src.views.fast_spdx import FastSPDX

    urls = [f"git+https://example.org/source-{i}.git@{str(i) * 40}" for i in (1, 2)]
    spdx_parser.packagesCtrl.add(Package("libc6", "2.41", source_urls=urls))
    output = json.loads(spdx_parser.output_as_json())
    binary = next(pkg for pkg in output["packages"] if pkg["name"] == "libc6")
    assert binary["versionInfo"] == "2.41"
    assert sorted(pkg["downloadLocation"] for pkg in output["packages"]
                  if pkg.get("primaryPackagePurpose") == "SOURCE") == urls
    controllers = ControllersCache()
    if fast:
        FastSPDX(controllers).parse_from_dict(output)
    else:
        parser = SPDX(controllers)
        parser.load_from_dict(output)
        parser.parse_and_merge()
    restored = controllers.packages.get("libc6@2.41")
    assert sorted(restored.source_urls) == urls
    assert restored.version_info["revision_conflict"]
