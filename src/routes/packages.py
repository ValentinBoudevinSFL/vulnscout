# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import uuid

from flask import Flask
from flask.typing import ResponseReturnValue

from ..models.sbom_package import SBOMPackage, PackageEvidence
from ._scan_queries import _package_rows
from ._evidence_scope import package_evidence, resolve_evidence_scope


def init_app(app: Flask) -> None:

    @app.route('/api/packages')
    def index_pkg() -> ResponseReturnValue:
        """List packages with optional project/variant comparison filters.

        Supports single-variant, project-wide, and multi-variant modes,
        including union/intersection/difference operations.

        OpenAPI:
        query variant_id uuid optional Filter by a single variant ID.
        query project_id uuid optional Filter by a single project ID.
        query compare_variant_id uuid optional Compare against a second variant ID.
        query variant_ids string optional Comma-separated list of variant IDs.
        query operation string optional Comparison mode such as difference, intersection, or union.
        query format string optional Response format such as list or dict.
        query package_id string optional Filter by the package string ID.
        query include_source_files boolean optional Include parsed source file and build details.
        query include_outdated boolean optional Include superseded package evidence within the selected scope.
        query outdated_only boolean optional Return only superseded package evidence.
        response 200 PackageCollection Filtered package collection; an array by default, or a map with format=dict.
        response 400 Error Invalid identifiers or missing scope for outdated packages.
        """
        from flask import request
        outdated_only = request.args.get('outdated_only', '').lower() in ('1', 'true', 'yes')
        if outdated_only and not any(request.args.get(key) for key in ("variant_id", "project_id", "variant_ids")):
            return {"error": "A variant or project scope is required for outdated packages"}, 400
        scope, err = resolve_evidence_scope(
            request.args, historical=True if outdated_only else None, allow_unscoped_cross_project=True,
        )
        if scope is None:
            return err if err is not None else ({"error": "Internal error"}, 500)
        evidence = package_evidence(scope)
        package_filter = request.args.get('package_id')
        include_source_files = request.args.get('include_source_files', '').lower() in ('1', 'true', 'yes')
        pkg_lookup = _package_rows(evidence.ids) if evidence.ids else {}
        pkg_lookup = {pid: pkg for pid, pkg in pkg_lookup.items()
                      if package_filter is None or pkg.string_id == package_filter}
        # Current package rows group active variants; historical-only memberships stay
        # separate so drill-down can select the exact variant even for repeated names.
        documents: dict[tuple[uuid.UUID, uuid.UUID | None], set[uuid.UUID]] = {}
        variants: dict[tuple[uuid.UUID, uuid.UUID | None], set[uuid.UUID]] = {}
        sources: dict[tuple[uuid.UUID, uuid.UUID | None], set[str]] = {}
        names: dict[tuple[uuid.UUID, uuid.UUID | None], set[str]] = {}
        contributors = set(scope.contributing_variants)
        for pid, doc, vid, scan, fmt, source in evidence.documents:
            if pid not in pkg_lookup or vid not in contributors:
                continue
            outdated = pid not in evidence.active_by_variant[vid]
            if outdated_only and not outdated:
                continue
            if not outdated and scan not in scope.active_sboms_by_variant[vid]:
                continue
            key = (pid, vid if outdated else None)
            documents.setdefault(key, set()).add(doc)
            variants.setdefault(key, set()).add(vid)
            if fmt:
                sources.setdefault(key, set()).add(fmt)
            if source:
                names.setdefault(key, set()).add(source)

        active_documents = set().union(*(docs for (_, vid), docs in documents.items() if vid is None))
        active_evidence = SBOMPackage.evidence_for_documents(
            active_documents, include_source_files=include_source_files, package_ids=set(pkg_lookup),
        )
        result = []
        for key in documents:
            pid, outdated_vid = key
            snapshot = pkg_lookup[pid].with_sbom_evidence(**active_evidence.get(
                pid, PackageEvidence(cpe=[], purl=[], source_urls=[]),
            ) if outdated_vid is None else PackageEvidence(cpe=[], purl=[], source_urls=[]))
            item = snapshot.to_dict()
            item.update({
                "variants": sorted({scope.variants[vid] for vid in variants[key]}),
                "inventory_variant_ids": sorted(str(vid) for vid in variants[key]),
                "sources": sorted(sources.get(key, set())),
                "sbom_documents": sorted(names.get(key, set())),
                "outdated": outdated_vid is not None,
            })
            if outdated_vid is not None:
                item["variant_id"] = str(outdated_vid)
            if include_source_files:
                item["source_files"] = snapshot.source_files
            result.append(item)
        result.sort(key=lambda item: (item["name"], item["version"], item["outdated"], item["variants"]))

        if request.args.get('format', 'list') == "dict":
            dict_result = {}
            for package in result:
                key = package["name"] + "@" + package["version"]
                if package["outdated"]:
                    key += "@" + package["variant_id"]
                dict_result[key] = package
            return dict_result
        return result
