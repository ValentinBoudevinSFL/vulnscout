"""Ingest real SBOM relationships and read their document-scoped API graphs."""

import json
import os

import pytest
from sqlalchemy import inspect, text

from src.bin.webapp import create_app
from src.bin.cmd_process import read_inputs
from src.controllers import ControllersCache
from src.extensions import db
from src.models import Finding, Package, PackageDependency, Project, SBOMDocument, SBOMPackage, Scan, Variant


@pytest.fixture()
def app(tmp_path):
    os.environ['FLASK_SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    try:
        application = create_app()
        status = tmp_path / 'scan-status'
        status.write_text('__END_OF_SCAN_SCRIPT__\n')
        application.config.update(TESTING=True, SCAN_FILE=str(status))
        with application.app_context():
            db.create_all()
            yield application
            db.session.remove()
            db.drop_all()
    finally:
        os.environ.pop('FLASK_SQLALCHEMY_DATABASE_URI', None)


def _scan(app, tmp_path, name, document, fmt='spdx'):
    with app.app_context():
        project = Project.get_all()[0] if Project.get_all() else Project.create('dep-project')
        variant = Variant.create(name, project.id)
        scan = Scan.create('SBOM', variant.id)
        path = tmp_path / f'{name}.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, scan.id, format=fmt)
        read_inputs(ControllersCache(), scan.id)
        return variant.id, scan.id


def _spdx3():
    return {'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        *({'type': 'software_Package', 'spdxId': f'pkg:{name}',
            'name': name, 'software_packageVersion': '1.0'} for name in ('app', 'lib', 'util')),
        {'type': 'LifecycleScopedRelationship', 'scope': 'build', 'relationshipType': 'dependsOn',
         'from': 'pkg:app', 'to': ['pkg:lib', 'pkg:util', 'pkg:missing']},
        {'type': 'Relationship', 'relationshipType': 'dependencyOf',
         'from': 'pkg:util', 'to': ['pkg:lib']},
        {'type': 'Relationship', 'relationshipType': 'describes',
         'from': 'pkg:app', 'to': ['pkg:util']},
    ]}


def _zephyr_spdx3(elements, namespace='https://example.org/zephyr/', prefix='zephyr'):
    return {'@context': 'https://spdx.org/rdf/3.0.1/spdx-context.jsonld', '@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        {'type': 'SoftwareAgent', 'name': 'West SPDX Generator'},
        {'type': 'SpdxDocument', 'namespaceMap': [
            {'type': 'NamespaceMap', 'prefix': prefix, 'namespace': namespace},
        ]},
        *elements,
    ]}


def test_zephyr_companion_documents_preserve_versions_and_build_dependencies(app, tmp_path):
    revision = 'a' * 40
    release_purl = 'pkg:github/Mbed-TLS/mbedtls@v4.1.1'
    release_cpe = 'cpe:2.3:a:trustedfirmware:mbed_tls:4.1.1:*:*:*:*:*:*:*'
    documents = {
        'app': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'zephyr:packages/app-sources',
             'name': 'app-sources', 'software_primaryPurpose': 'source'},
        ]),
        'build': _zephyr_spdx3([
            *({'type': 'software_Package', 'spdxId': f'zephyr:packages/{name}',
               'name': name, 'software_primaryPurpose': 'library'}
              for name in ('app', 'mbedtls', 'tfpsacrypto')),
            {'type': 'Relationship', 'relationshipType': 'hasPrerequisite',
             'from': 'zephyr:packages/app', 'to': ['zephyr:packages/mbedtls']},
            {'type': 'Relationship', 'relationshipType': 'hasPrerequisite',
             'from': 'zephyr:packages/mbedtls', 'to': ['zephyr:packages/tfpsacrypto']},
            {'type': 'Relationship', 'relationshipType': 'contains',
             'from': 'zephyr:packages/app', 'to': ['zephyr:files/libapp.a']},
            {'type': 'software_File', 'spdxId': 'zephyr:files/libapp.a', 'name': 'libapp.a'},
            {'type': 'Relationship', 'relationshipType': 'hasStaticLink',
             'from': 'zephyr:files/libapp.a', 'to': ['zephyr:files/libmbedtls.a']},
        ]),
        'modules-deps': _zephyr_spdx3([
            *({'type': 'software_Package', 'spdxId': f'zephyr:packages/{name}-deps',
               'name': f'{name}-deps', 'software_packageVersion': revision,
               'software_primaryPurpose': 'library',
               'externalIdentifier': [
                   {'type': 'ExternalIdentifier', 'externalIdentifierType': 'packageUrl',
                    'identifier': release_purl},
                   {'type': 'ExternalIdentifier', 'externalIdentifierType': 'cpe23',
                    'identifier': release_cpe},
               ] if name == 'mbedtls' else []}
              for name in ('zephyr', 'mbedtls')),
            {'type': 'Relationship', 'relationshipType': 'dependsOn',
             'from': 'zephyr:packages/zephyr-deps', 'to': ['zephyr:packages/mbedtls-deps']},
        ]),
        'zephyr': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'zephyr:packages/mbedtls-sources',
             'name': 'mbedtls-sources', 'software_packageVersion': revision,
             'software_primaryPurpose': 'source'},
            {'type': 'Relationship', 'relationshipType': 'hasVariant',
             'from': 'zephyr:packages/mbedtls-deps', 'to': ['zephyr:packages/mbedtls-sources']},
        ]),
    }
    with app.app_context():
        project = Project.create('zephyr')
        variant = Variant.create('demo', project.id)
        variant_id = variant.id
        scan = Scan.create('SBOM', variant.id)
        scan_id = scan.id
        for name, document in documents.items():
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        assert len(Package.get_all()) == 7
        module = Package.get_by_string_id(f'mbedtls-deps@{revision}')
        assert module.version == revision
        assert 'pkg:github/mbed-tls/mbedtls@v4.1.1' in module.purl
        assert release_cpe in module.cpe
        assert Package.get_by_string_id('mbedtls@').version == ''
        assert Package.get_by_string_id(f'mbedtls-sources@{revision}') is not None

    client = app.test_client()
    response = client.get(f'/api/package-dependencies?variant_id={variant_id}')
    assert response.status_code == 200
    graphs = {document['source_name']: document for document in response.json['documents']}
    assert {name: len(graph['packages']) for name, graph in graphs.items()} == {
        'app.jsonld': 1, 'build.jsonld': 3, 'modules-deps.jsonld': 2, 'zephyr.jsonld': 1,
    }
    assert graphs['build.jsonld']['edges'] == [
        {'package_id': 'app@', 'dependency_id': 'mbedtls@'},
        {'package_id': 'mbedtls@', 'dependency_id': 'tfpsacrypto@'},
    ]
    assert graphs['modules-deps.jsonld']['edges'] == [
        {'package_id': f'zephyr-deps@{revision}', 'dependency_id': f'mbedtls-deps@{revision}'},
    ]
    module_graph = next(package for package in graphs['modules-deps.jsonld']['packages']
                        if package['name'] == 'mbedtls-deps')
    assert module_graph['version'] == module_graph['source_revision'] == revision
    assert module_graph['release_version'] == '4.1.1'
    package_response = client.get(f'/api/packages?variant_id={variant_id}&format=list')
    assert package_response.status_code == 200
    module_api = next(package for package in package_response.json if package['name'] == 'mbedtls-deps')
    assert module_api['release_version'] == '4.1.1'
    assert module_api['source_revision'] == revision
    assert module_api['id'] == f'mbedtls-deps@{revision}'
    assert {item['source'] for item in module_api['version_evidence']} == {'sbom', 'purl', 'cpe'}
    assert graphs['app.jsonld']['edges'] == graphs['zephyr.jsonld']['edges'] == []
    assert client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json['counts'] == {
        'app@': {'in': 1, 'out': 0}, 'mbedtls@': {'in': 1, 'out': 1}, 'tfpsacrypto@': {'in': 0, 'out': 1},
        f'zephyr-deps@{revision}': {'in': 1, 'out': 0}, f'mbedtls-deps@{revision}': {'in': 0, 'out': 1},
    }
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
        assert db.session.query(PackageDependency).count() == 3


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('source_ref', ['zephyr:packages/app', 'app-ref'])
def test_spdx3_dependencies_resolve_namespaces_and_companion_documents(app, tmp_path, reverse, source_ref):
    documents = {
        'app': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': source_ref, 'name': 'app'},
            {'type': 'LifecycleScopedRelationship', 'scope': 'build', 'relationshipType': 'hasPrerequisite',
             'from': source_ref, 'to': ['https://example.org/zephyr/packages/lib']},
            {'type': 'Relationship', 'relationshipType': 'dependsOn', 'from': source_ref,
             'to': ['zephyr:packages/missing']},
        ]),
        'lib': _zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'companion:packages/lib', 'name': 'lib'},
            {'type': 'Relationship', 'relationshipType': 'dependencyOf',
             'from': 'companion:packages/lib', 'to': ['companion:packages/app']},
        ], prefix='companion'),
    }
    with app.app_context():
        project = Project.create('cross-document')
        variant = Variant.create('demo', project.id)
        variant_id = variant.id
        scan = Scan.create('SBOM', variant.id)
        scan_id = scan.id
        for name in sorted(documents, reverse=reverse):
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(documents[name]))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan.id)
        rows = db.session.execute(
            db.select(SBOMDocument.source_name, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        ).all()
        names = {package.id: package.name for package in Package.get_all()}
        assert [(source, names[package], names[dependency]) for source, package, dependency in rows] == [
            ('app.jsonld', 'app', 'lib'),
        ]

    client = app.test_client()
    assert client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json['counts'] == {
        'app@': {'in': 1, 'out': 0}, 'lib@': {'in': 0, 'out': 1},
    }
    graphs = {document['source_name']: document for document in client.get(
        f'/api/package-dependencies?variant_id={variant_id}'
    ).json['documents']}
    assert graphs['app.jsonld']['edges'] == [{'package_id': 'app@', 'dependency_id': 'lib@'}]
    assert graphs['lib.jsonld']['edges'] == []

    for name, document in documents.items():
        document['@graph'] = [item for item in document['@graph'] if 'relationshipType' not in item]
        (tmp_path / f'{name}.jsonld').write_text(json.dumps(document))
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
        assert db.session.query(PackageDependency).count() == 0


def test_spdx3_uri_references_do_not_leak_across_scans_or_namespaces(app, tmp_path):
    with app.app_context():
        project = Project.create('isolated')
        for name, namespace, packages in (
            ('other-scan', 'https://example.org/zephyr/', ('lib',)),
            ('current-scan', 'https://example.org/unrelated/', ('lib',)),
        ):
            variant = Variant.create(name, project.id)
            scan = Scan.create('SBOM', variant.id)
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(_zephyr_spdx3([
                {'type': 'software_Package', 'spdxId': f'zephyr:packages/{package}',
                 'name': f'{name}-{package}'} for package in packages
            ], namespace=namespace)))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        path = tmp_path / 'dependent.jsonld'
        path.write_text(json.dumps(_zephyr_spdx3([
            {'type': 'software_Package', 'spdxId': 'zephyr:packages/app', 'name': 'app'},
            {'type': 'Relationship', 'relationshipType': 'dependsOn',
             'from': 'zephyr:packages/app', 'to': ['zephyr:packages/lib']},
        ])))
        SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache())
        assert db.session.query(PackageDependency).count() == 0


@pytest.mark.parametrize('namespace_map', [None, 123, 'invalid'])
def test_invalid_spdx3_namespace_map_keeps_local_dependencies(app, tmp_path, caplog, namespace_map):
    document = _spdx3()
    document['@graph'].append({'type': 'SpdxDocument', 'namespaceMap': namespace_map})
    variant_id, _ = _scan(app, tmp_path, 'invalid-map', document)
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}').json['documents'][0]
    assert len(graph['edges']) == 3
    assert 'Skipping invalid SPDX namespaceMap' in caplog.text


def _yocto_spdx2(name, packages=(), refs=(), relationships=()):
    """Build one per-recipe/per-package document of a Yocto SPDX 2.2 archive."""
    return {
        'spdxVersion': 'SPDX-2.2', 'SPDXID': 'SPDXRef-DOCUMENT', 'name': name, 'dataLicense': 'CC0-1.0',
        'documentNamespace': f'http://spdx.org/spdxdocs/{name}',
        'creationInfo': {'creators': ['Tool: test'], 'created': '2024-01-01T00:00:00Z'},
        'externalDocumentRefs': [
            {'externalDocumentId': ref, 'spdxDocument': f'http://spdx.org/spdxdocs/{target}',
             'checksum': {'algorithm': 'SHA1', 'checksumValue': '0' * 40}}
            for ref, target in refs
        ],
        'packages': [{'SPDXID': spdx_id, 'name': package, 'versionInfo': '1.0', 'downloadLocation': 'NOASSERTION'}
                     for spdx_id, package in packages],
        'relationships': [{'spdxElementId': source, 'relationshipType': kind, 'relatedSpdxElement': target}
                          for source, kind, target in relationships],
    }


def _yocto_archive():
    return {
        'runtime-app': _yocto_spdx2('runtime-app', refs=(
            ('DocumentRef-app', 'recipe-app'), ('DocumentRef-util', 'util'), ('DocumentRef-ghost', 'ghost'),
        ), relationships=(
            ('DocumentRef-util:SPDXRef-Package-util', 'RUNTIME_DEPENDENCY_OF', 'DocumentRef-app:SPDXRef-Recipe-app'),
            ('DocumentRef-ghost:SPDXRef-Package-ghost', 'RUNTIME_DEPENDENCY_OF', 'DocumentRef-app:SPDXRef-Recipe-app'),
            ('DocumentRef-unknown:SPDXRef-Package-x', 'RUNTIME_DEPENDENCY_OF', 'DocumentRef-app:SPDXRef-Recipe-app'),
        )),
        'recipe-app': _yocto_spdx2('recipe-app', packages=(('SPDXRef-Recipe-app', 'app'),), refs=(
            ('DocumentRef-dependency-recipe-lib', 'recipe-lib'),
        ), relationships=(
            ('DocumentRef-dependency-recipe-lib:SPDXRef-Recipe-lib', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-app'),
        )),
        'recipe-lib': _yocto_spdx2('recipe-lib', packages=(('SPDXRef-Recipe-lib', 'lib'),)),
        'util': _yocto_spdx2('util', packages=(('SPDXRef-Package-util', 'util'),)),
    }


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
@pytest.mark.parametrize('reverse', [False, True])
def test_yocto_spdx2_source_revisions_resolve_recipes_without_toolchain_contamination(
        app, tmp_path, monkeypatch, ignore_parsing_errors, reverse):
    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    revision, compiler_revision = 'a' * 40, 'b' * 40
    url = f'git+https://example.org/glibc.git@{revision}'
    recipe = _yocto_spdx2('recipe-glibc', packages=(
        ('SPDXRef-Recipe-glibc', 'glibc'), ('SPDXRef-Download-glibc', 'glibc-source'),
    ), refs=(('DocumentRef-compiler', 'recipe-compiler'),), relationships=(
        ('SPDXRef-Download-glibc', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-glibc'),
        ('DocumentRef-compiler:SPDXRef-Recipe-compiler', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-glibc'),
    ))
    recipe['packages'][0]['versionInfo'] = '2.41+git'
    recipe['packages'][1].pop('versionInfo')
    recipe['packages'][1]['downloadLocation'] = url
    binary = _yocto_spdx2('libc6', packages=(('SPDXRef-Package-libc6', 'libc6'),),
                         refs=(('DocumentRef-glibc', 'recipe-glibc'),), relationships=(
                             ('SPDXRef-Package-libc6', 'GENERATED_FROM',
                              'DocumentRef-glibc:SPDXRef-Recipe-glibc'),
                         ))
    binary['packages'][0]['versionInfo'] = '2.41+git'
    binary['packages'][0]['checksums'] = [{'algorithm': 'SHA1', 'checksumValue': 'f' * 40}]
    compiler = _yocto_spdx2('recipe-compiler', packages=(
        ('SPDXRef-Recipe-compiler', 'compiler'), ('SPDXRef-Download-compiler', 'compiler-source'),
    ), relationships=(('SPDXRef-Download-compiler', 'BUILD_DEPENDENCY_OF', 'SPDXRef-Recipe-compiler'),))
    compiler['packages'][1].pop('versionInfo')
    compiler['packages'][1]['downloadLocation'] = f'git+https://example.org/compiler.git@{compiler_revision}'
    unrelated = _yocto_spdx2('other-libc', packages=(('SPDXRef-other', 'other-libc'),),
                            refs=(('DocumentRef-glibc', 'recipe-glibc'),), relationships=(
                                ('SPDXRef-other', 'GENERATED_FROM', 'DocumentRef-glibc:SPDXRef-Recipe-glibc'),
                            ))
    with app.app_context():
        project = Project.create('yocto-source')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)
        scan_id, variant_id = scan.id, variant.id
        documents = [('recipe', recipe), ('binary', binary), ('compiler', compiler)]
        for name, document in reversed(documents) if reverse else documents:
            path = tmp_path / f'{name}.spdx.json'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        other_variant = Variant.create('other', project.id)
        other_scan = Scan.create('SBOM', other_variant.id)
        path = tmp_path / 'other.spdx.json'
        path.write_text(json.dumps(unrelated))
        SBOMDocument.create(str(path), path.name, other_scan.id, format='spdx')
        read_inputs(ControllersCache())
        db.session.remove()
        libc = Package.get_by_string_id('libc6@2.41')
        assert libc.source_urls == [url]
        assert libc.version_info['release_version'] == '2.41'
        assert libc.version_info['source_revision'] == revision
        assert not libc.version_info['revision_conflict']
        assert Package.get_by_string_id('glibc@2.41').source_urls == [url]
        assert Package.get_by_string_id('compiler@1.0').version_info['source_revision'] == compiler_revision
        assert Package.get_by_string_id('other-libc@1.0').source_urls == []
        read_inputs(ControllersCache(), scan_id)
        assert Package.get_by_string_id('libc6@2.41').source_urls == [url]

    client = app.test_client()
    result = client.get(f'/api/packages?variant_id={variant_id}&format=list').json
    libc = next(package for package in result if package['name'] == 'libc6')
    assert libc['source_revision'] == revision
    assert libc['version_evidence'][-1] == {'source': 'download', 'version': revision, 'identifier': url}
    graph = client.get(f'/api/package-dependencies?variant_id={variant_id}').json
    assert next(pkg for doc in graph['documents'] for pkg in doc['packages']
                if pkg['name'] == 'libc6')['source_revision'] == revision


@pytest.mark.parametrize('multiple_sources', [False, True])
def test_yocto_spdx3_source_build_outputs_preserve_provenance_without_image_or_checksum_inheritance(
        app, tmp_path, multiple_sources):
    revision = 'a' * 40
    urls = [f'git+https://example.org/glibc.git@{revision}']
    if multiple_sources:
        urls.append(f'git+https://example.org/config.git@{"b" * 40}')
    sources = _zephyr_spdx3([
        {'type': 'build_Build', 'spdxId': 'zephyr:build/recipe'},
        *({'type': 'software_Package', 'spdxId': f'zephyr:source/{i}',
           'name': f'source-{i}', 'software_primaryPurpose': 'source', 'software_downloadLocation': url}
          for i, url in enumerate(urls)),
        {'type': 'software_File', 'spdxId': 'zephyr:patch', 'name': 'patch',
         'verifiedUsing': [{'type': 'Hash', 'algorithm': 'sha1', 'hashValue': 'f' * 40}]},
    ])
    # This is a Yocto document, not West: source nodes must remain filtered.
    sources['@graph'] = [item for item in sources['@graph'] if item.get('type') != 'SoftwareAgent']
    build = _zephyr_spdx3([
        {'type': 'build_Build', 'spdxId': 'zephyr:build/image'},
        {'type': 'software_Package', 'spdxId': 'zephyr:binary', 'name': 'libc6',
         'software_packageVersion': '2.41+git', 'software_primaryPurpose': 'install'},
        {'type': 'software_Package', 'spdxId': 'zephyr:image', 'name': 'image', 'software_packageVersion': '1'},
        {'type': 'software_Package', 'spdxId': 'zephyr:direct', 'name': 'direct', 'software_packageVersion': '1',
         'software_downloadLocation': f'git+https://example.org/direct.git@{"c" * 40}'},
        {'type': 'Relationship', 'from': 'https://example.org/zephyr/build/recipe', 'relationshipType': 'hasInput',
         'to': [*(f'zephyr:source/{i}' for i in range(len(urls))), 'zephyr:patch']},
        {'type': 'Relationship', 'from': 'zephyr:build/recipe', 'relationshipType': 'hasOutput', 'to': 'zephyr:binary'},
        {'type': 'Relationship', 'from': 'zephyr:build/image', 'relationshipType': 'hasInput',
         'to': ['zephyr:binary', 'zephyr:direct']},
        {'type': 'Relationship', 'from': 'zephyr:build/image', 'relationshipType': 'hasOutput', 'to': ['zephyr:image']},
        {'type': 'Relationship', 'from': 'zephyr:unknown-build', 'relationshipType': 'hasInput',
         'to': ['zephyr:source/0']},
        {'type': 'Relationship', 'from': 'zephyr:unknown-build', 'relationshipType': 'hasOutput',
         'to': ['zephyr:image']},
    ])
    with app.app_context():
        project = Project.create('yocto-spdx3-source')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)
        scan_id = scan.id
        for name, document in [('build', build), ('sources', sources)]:
            path = tmp_path / f'{name}.jsonld'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache(), scan_id)
        db.session.remove()
        assert len(Package.get_all()) == 3
        binary = Package.get_by_string_id('libc6@2.41')
        assert binary.source_urls == sorted(urls)
        assert binary.version_info['release_version'] == '2.41'
        assert binary.version_info['source_revision'] == (None if multiple_sources else revision)
        assert binary.version_info['revision_conflict'] == multiple_sources
        assert Package.get_by_string_id('direct@1').version_info['source_revision'] == 'c' * 40
        assert Package.get_by_string_id('image@1').source_urls == []
        assert db.session.query(PackageDependency).count() == 0
        read_inputs(ControllersCache(), scan_id)
        assert Package.get_by_string_id('libc6@2.41').source_urls == sorted(urls)


@pytest.mark.parametrize('ignore_parsing_errors', ['false', 'true'])
def test_yocto_spdx2_dependencies_resolve_across_documents_of_one_scan(
        app, tmp_path, monkeypatch, ignore_parsing_errors):
    monkeypatch.setenv('IGNORE_PARSING_ERRORS', ignore_parsing_errors)
    with app.app_context():
        project = Project.create('yocto')
        project_id = project.id
        variants = [Variant.create(name, project.id) for name in ('first', 'second')]
        first_variant_id = variants[0].id
        for variant in variants:
            scan = Scan.create('SBOM', variant.id)
            for name, document in _yocto_archive().items():
                path = tmp_path / f'{variant.name}-{name}.spdx.json'
                path.write_text(json.dumps(document))
                SBOMDocument.create(str(path), path.name, scan.id, format='spdx')
        read_inputs(ControllersCache())

        rows = db.session.execute(
            db.select(SBOMDocument.source_name, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        ).all()
        names = {package.id: package.name for package in Package.get_all()}
        assert sorted((source, names[package], names[dependency]) for source, package, dependency in rows) == [
            ('first-recipe-app.spdx.json', 'app', 'lib'), ('first-recipe-app.spdx.json', 'app', 'util'),
            ('second-recipe-app.spdx.json', 'app', 'lib'), ('second-recipe-app.spdx.json', 'app', 'util'),
        ]

    client = app.test_client()
    assert client.get(f'/api/package-dependencies?variant_id={first_variant_id}&counts=1').json['counts'] == {
        'app@1.0': {'in': 2, 'out': 0}, 'lib@1.0': {'in': 0, 'out': 1}, 'util@1.0': {'in': 0, 'out': 1},
    }
    documents = client.get(f'/api/package-dependencies?project_id={project_id}').json['documents']
    assert [(document['variant_name'], document['source_name'], len(document['edges']))
            for document in documents if document['edges']] == [
        ('first', 'first-recipe-app.spdx.json', 2), ('second', 'second-recipe-app.spdx.json', 2),
    ]

    recipe = _yocto_archive()['recipe-app']
    recipe['relationships'] = []
    (tmp_path / 'first-recipe-app.spdx.json').write_text(json.dumps(recipe))
    with app.app_context():
        read_inputs(ControllersCache())
        assert sorted((source, names[package], names[dependency]) for source, package, dependency in db.session.execute(
            db.select(SBOMDocument.source_name, PackageDependency.package_id, PackageDependency.dependency_id)
            .join(SBOMDocument, SBOMDocument.id == PackageDependency.sbom_document_id)
        )) == [
            ('first-recipe-app.spdx.json', 'app', 'util'),
            ('second-recipe-app.spdx.json', 'app', 'lib'), ('second-recipe-app.spdx.json', 'app', 'util'),
        ]


def test_spdx3_ingestion_and_scoped_api(app, tmp_path):
    variant, scan_id = _scan(app, tmp_path, 'one', _spdx3())
    client = app.test_client()
    response = client.get(f'/api/package-dependencies?variant_id={variant}')
    assert response.status_code == 200
    document = response.json['documents'][0]
    assert (document['variant_id'], document['variant_name']) == (str(variant), 'one')
    names = {package['id']: package['name'] for package in document['packages']}
    assert set(names) == {'app@1.0', 'lib@1.0', 'util@1.0'}
    assert set(names.values()) == {'app', 'lib', 'util'}
    assert {(names[edge['package_id']], names[edge['dependency_id']]) for edge in document['edges']} == {
        ('app', 'lib'), ('app', 'util'), ('lib', 'util'),
    }
    counts = client.get(f'/api/package-dependencies?variant_id={variant}&counts=1').json['counts']
    assert counts == {
        'app@1.0': {'in': 2, 'out': 0},
        'lib@1.0': {'in': 1, 'out': 1},
        'util@1.0': {'in': 0, 'out': 2},
    }
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
        assert db.session.query(PackageDependency).count() == 3

    other, _ = _scan(app, tmp_path, 'two', {
        '@graph': [{'type': 'CreationInfo', 'specVersion': '3.0.1'},
                   {'type': 'software_Package', 'spdxId': 'pkg:a', 'name': 'app', 'software_packageVersion': '1.0'},
                   {'type': 'software_Package', 'spdxId': 'pkg:b', 'name': 'other', 'software_packageVersion': '1.0'},
                   {'type': 'Relationship', 'relationshipType': 'dependsOn', 'from': 'pkg:a', 'to': ['pkg:b']}],
    })
    assert len(client.get(f'/api/package-dependencies?variant_id={variant}').json['documents']) == 1
    assert len(client.get(f'/api/package-dependencies?variant_id={other}').json['documents']) == 1
    project_id = client.get(f'/api/package-dependencies?variant_ids={variant},{other}').json['documents']
    assert len(project_id) == 2
    assert len(client.get(f'/api/package-dependencies?project_id={Project.get_all()[0].id}').json['documents']) == 2
    assert client.get('/api/package-dependencies').status_code == 400
    assert client.get('/api/package-dependencies?variant_id=invalid').status_code == 400
    assert client.get('/api/package-dependencies?variant_ids=,').status_code == 400


@pytest.mark.parametrize('format_name', ['spdx3', 'spdx2', 'cdx'])
def test_document_references_do_not_resolve_through_previous_document(app, tmp_path, format_name):
    with app.app_context():
        project = Project.create(f'{format_name}-project')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)

        def document(source_ref, lib_ref, target_refs):
            if format_name == 'spdx3':
                return {'@graph': [
                    {'type': 'CreationInfo', 'specVersion': '3.0.1'},
                    *({'type': 'software_Package', 'spdxId': ref, 'name': name,
                        'software_packageVersion': '1.0'}
                      for ref, name in ((source_ref, 'app'), (lib_ref, 'lib'))),
                    {'type': 'Relationship', 'relationshipType': 'dependsOn',
                     'from': source_ref, 'to': target_refs},
                ]}
            if format_name == 'spdx2':
                return {
                    'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT',
                    'creationInfo': {'creators': ['Tool: test'], 'created': '2024-01-01T00:00:00Z'},
                    'name': 'test', 'dataLicense': 'CC0-1.0',
                    'documentNamespace': f'https://example.org/{source_ref}',
                    'packages': [
                        {'SPDXID': ref, 'name': name, 'versionInfo': '1.0',
                         'downloadLocation': 'NOASSERTION'}
                        for ref, name in ((source_ref, 'app'), (lib_ref, 'lib'))
                    ],
                    'relationships': [
                        {'spdxElementId': source_ref, 'relationshipType': 'DEPENDS_ON',
                         'relatedSpdxElement': target} for target in target_refs
                    ],
                }
            return {
                'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                'components': [
                    {'type': 'library', 'bom-ref': ref, 'name': name, 'version': '1.0'}
                    for ref, name in ((source_ref, 'app'), (lib_ref, 'lib'))
                ],
                'dependencies': [{'ref': source_ref, 'dependsOn': target_refs}],
            }

        for name, source, lib, targets in (
            ('a', 'app-a', 'lib-a', ['lib-a']),
            ('b', 'app-b', 'lib-b', ['lib-a']),
        ):
            path = tmp_path / f'{name}.json'
            path.write_text(json.dumps(document(source, lib, targets)))
            SBOMDocument.create(str(path), path.name, scan.id,
                                format='cdx' if format_name == 'cdx' else 'spdx')

        read_inputs(ControllersCache(), scan.id)
        documents = SBOMDocument.get_by_scan(scan.id)
        assert [document.source_name for document in documents] == ['a.json', 'b.json']
        assert [db.session.query(PackageDependency).filter_by(sbom_document_id=doc.id).count()
            for doc in documents] == [1, 0]


def test_cdx_vulnerabilities_still_resolve_components_from_previous_document(app, tmp_path):
    with app.app_context():
        project = Project.create('vex-project')
        variant = Variant.create('default', project.id)
        scan = Scan.create('SBOM', variant.id)
        documents = {
            'sbom': {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                     'components': [{'type': 'library', 'bom-ref': 'app-ref', 'name': 'app', 'version': '1.0'}]},
            'vex': {'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
                    'vulnerabilities': [{'id': 'CVE-2024-0001', 'affects': [{'ref': 'app-ref'}]}]},
        }
        for name, document in documents.items():
            path = tmp_path / f'{name}.json'
            path.write_text(json.dumps(document))
            SBOMDocument.create(str(path), path.name, scan.id, format='cdx')

        read_inputs(ControllersCache(), scan.id)
        findings = db.session.execute(
            db.select(Finding.vulnerability_id).join(Package, Package.id == Finding.package_id)
            .where(Package.name == 'app')
        ).scalars().all()
        assert findings == ['CVE-2024-0001']


def test_reingesting_document_replaces_removed_relationships(app, tmp_path):
    variant, scan_id = _scan(app, tmp_path, 'updated', _spdx3())
    replacement = _spdx3()
    replacement['@graph'] = [
        item for item in replacement['@graph']
        if item.get('relationshipType') != 'dependsOn'
    ]
    (tmp_path / 'updated.json').write_text(json.dumps(replacement))

    with app.app_context():
        read_inputs(ControllersCache(), scan_id)

    document = app.test_client().get(f'/api/package-dependencies?variant_id={variant}').json['documents'][0]
    names = {package['id']: package['name'] for package in document['packages']}
    assert {(names[edge['package_id']], names[edge['dependency_id']]) for edge in document['edges']} == {
        ('lib', 'util'),
    }


def test_deleting_scan_removes_dependency_edges(app, tmp_path):
    _, scan_id = _scan(app, tmp_path, 'removed', _spdx3())
    with app.app_context():
        assert db.session.query(PackageDependency).count() == 3
        Scan.get_by_id(scan_id).delete()
        assert db.session.query(PackageDependency).count() == 0


def test_deleting_package_link_removes_incoming_and_outgoing_edges(app, tmp_path):
    _, scan_id = _scan(app, tmp_path, 'link', _spdx3())
    with app.app_context():
        document_id = SBOMDocument.get_by_scan(scan_id)[0].id
        linked = SBOMPackage.get_by_document(document_id)
        app_link = next(link for link in linked if link.package.name == 'app')
        app_link.delete()
        assert db.session.query(PackageDependency).count() == 1
        util_link = next(link for link in linked if link.package.name == 'util')
        util_link.delete()
        assert db.session.query(PackageDependency).count() == 0


def test_deleting_package_removes_incoming_and_outgoing_edges(app, tmp_path):
    variant_id, _ = _scan(app, tmp_path, 'package', _spdx3())
    with app.app_context():
        assert ControllersCache().packages.remove('lib@1.0')
        names = {package.id: package.name for package in Package.get_all()}
        assert [(names[edge.package_id], names[edge.dependency_id])
                for edge in db.session.query(PackageDependency)] == [('app', 'util')]

    client = app.test_client()
    counts = client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1')
    assert counts.status_code == 200
    assert counts.json['counts'] == {'app@1.0': {'in': 1, 'out': 0}, 'util@1.0': {'in': 0, 'out': 1}}
    graph = client.get(f'/api/package-dependencies?variant_id={variant_id}')
    assert graph.status_code == 200
    assert graph.json['documents'][0]['edges'] == [{'package_id': 'app@1.0', 'dependency_id': 'util@1.0'}]


def test_documents_without_recorded_dependencies_are_not_reported_as_zero(app, tmp_path):
    variant_id, scan_id = _scan(app, tmp_path, 'recorded', _spdx3())
    with app.app_context():
        assert [document.dependencies_recorded for document in SBOMDocument.get_by_scan(scan_id)] == [True]
        # An SBOM merged before dependency support: its source file was removed after import.
        legacy_path = tmp_path / 'legacy.json'
        legacy = SBOMDocument.create(str(legacy_path), legacy_path.name, scan_id, format='spdx')
        legacy_id = legacy.id
        legacy_package = Package.create('legacy', '2.0')
        db.session.add(SBOMPackage(sbom_document_id=legacy.id, package_id=legacy_package.id))
        db.session.commit()
        read_inputs(ControllersCache(), scan_id)
        assert db.session.get(SBOMDocument, legacy_id).dependencies_recorded is False

    client = app.test_client()
    counts = client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json
    assert counts['unrecorded'] == ['legacy@2.0']
    assert 'legacy@2.0' not in counts['counts']
    documents = client.get(f'/api/package-dependencies?variant_id={variant_id}').json['documents']
    assert {document['source_name']: document['dependencies_recorded'] for document in documents} == {
        'legacy.json': False, 'recorded.json': True,
    }

    # Importing the source file again records its relationships.
    legacy_path.write_text(json.dumps({'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        {'type': 'software_Package', 'spdxId': 'pkg:legacy', 'name': 'legacy', 'software_packageVersion': '2.0'},
    ]}))
    with app.app_context():
        read_inputs(ControllersCache(), scan_id)
    assert client.get(f'/api/package-dependencies?variant_id={variant_id}&counts=1').json['unrecorded'] == []
    assert client.get('/api/package-dependencies?variant_id=00000000-0000-0000-0000-000000000000&counts=1').json == {
        'counts': {}, 'unrecorded': [],
    }


def test_outdated_cleanup_keeps_reactivated_graph_consistent(app, tmp_path):
    variant_id, older_scan_id = _scan(app, tmp_path, 'older', _spdx3())
    with app.app_context():
        newer_scan = Scan.create('SBOM', variant_id)
        document = {'@graph': [
            {'type': 'CreationInfo', 'specVersion': '3.0.1'},
            {'type': 'software_Package', 'spdxId': 'pkg:app',
             'name': 'app', 'software_packageVersion': '1.0'},
        ]}
        path = tmp_path / 'newer.json'
        path.write_text(json.dumps(document))
        SBOMDocument.create(str(path), path.name, newer_scan.id, format='spdx')
        read_inputs(ControllersCache(), newer_scan.id)

        from src.helpers.outdated_cleanup import delete_outdated_data
        assert delete_outdated_data()['sbom_packages_deleted'] == 2
        assert db.session.query(PackageDependency).count() == 0
        newer_scan.delete()

    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant_id}')
    assert graph.status_code == 200
    assert graph.json['documents'][0]['edges'] == []
    with app.app_context():
        assert Scan.get_by_id(older_scan_id) is not None


def test_comparison_graph_matches_package_selection(app, tmp_path):
    base_id, _ = _scan(app, tmp_path, 'base', _spdx3())
    compare_id, _ = _scan(app, tmp_path, 'compare', {'@graph': [
        {'type': 'CreationInfo', 'specVersion': '3.0.1'},
        *({'type': 'software_Package', 'spdxId': f'pkg:{name}',
            'name': name, 'software_packageVersion': '1.0'}
          for name in ('app', 'core', 'other')),
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'pkg:app', 'to': ['pkg:core']},
        {'type': 'Relationship', 'relationshipType': 'dependsOn',
         'from': 'pkg:core', 'to': ['pkg:other']},
    ]})
    client = app.test_client()
    for operation, expected_names, expected_edges in (
        ('difference', {'core', 'other'}, 1),
        ('intersection', {'app'}, 0),
    ):
        query = f'variant_id={base_id}&compare_variant_id={compare_id}&operation={operation}'
        packages = client.get(f'/api/packages?{query}').json
        graph = client.get(f'/api/package-dependencies?{query}')
        assert graph.status_code == 200
        documents = graph.json['documents']
        assert len(documents) == (1 if operation == 'difference' else 2)
        assert {package['name'] for doc in documents for package in doc['packages']} == expected_names
        assert {package['name'] for package in packages} == expected_names
        assert sum(len(doc['edges']) for doc in documents) == expected_edges
        counts = client.get(f'/api/package-dependencies?{query}&counts=1').json['counts']
        assert counts == ({'core@1.0': {'in': 1, 'out': 0}, 'other@1.0': {'in': 0, 'out': 1}}
                          if operation == 'difference' else {})

    intersection = client.get(
        f'/api/package-dependencies?variant_ids={base_id},{compare_id}&operation=intersection'
    )
    assert intersection.status_code == 200
    assert {package['name'] for doc in intersection.json['documents']
            for package in doc['packages']} == {'app'}

    union = client.get(f'/api/package-dependencies?variant_ids={base_id}&compare_variant_id={compare_id}')
    assert union.status_code == 200
    assert {package['name'] for doc in union.json['documents']
            for package in doc['packages']} == {'app', 'lib', 'util'}


@pytest.mark.parametrize('format_name,document', [
    ('spdx', {
        'spdxVersion': 'SPDX-2.3', 'SPDXID': 'SPDXRef-DOCUMENT',
        'creationInfo': {'creators': ['Tool: test'], 'created': '2024-01-01T00:00:00Z'},
        'name': 'test', 'dataLicense': 'CC0-1.0', 'documentNamespace': 'https://example.org/deps',
        'packages': [{'SPDXID': f'SPDXRef-{name}', 'name': name, 'versionInfo': '1.0',
                      'downloadLocation': 'NOASSERTION'} for name in ('app', 'lib')],
        'relationships': [{'spdxElementId': 'SPDXRef-app', 'relationshipType': 'DEPENDS_ON',
                           'relatedSpdxElement': 'SPDXRef-lib'}],
    }),
    ('cdx', {
        'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1,
        'components': [{'type': 'library', 'bom-ref': name, 'name': name, 'version': '1.0'}
                       for name in ('app', 'lib')],
        'dependencies': [{'ref': 'app', 'dependsOn': ['lib']}],
    }),
])
def test_supported_formats_ingest_dependencies(app, tmp_path, format_name, document):
    variant, _ = _scan(app, tmp_path, format_name, document, format_name)
    graph = app.test_client().get(f'/api/package-dependencies?variant_id={variant}').json['documents'][0]
    assert len(graph['packages']) == 2
    assert len(graph['edges']) == 1


def test_migration_creates_composite_membership_constraints(app):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    migration = import_module('src.migrations.versions.d8e2a1c7b9f0_add_package_dependencies')
    with app.app_context(), db.engine.begin() as connection:
        PackageDependency.__table__.drop(connection)
        context = MigrationContext.configure(connection)
        with Operations.context(context):
            migration.upgrade()
            keys = inspect(connection).get_foreign_keys('package_dependencies')
            assert sum(key['referred_table'] == 'sbom_packages' for key in keys) == 1
            assert any(key['referred_table'] == 'packages' for key in keys)
            migration.downgrade()
        assert 'package_dependencies' not in inspect(connection).get_table_names()


def test_migration_flags_only_documents_of_scans_with_recorded_edges(app, tmp_path):
    from importlib import import_module
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    _, parsed_scan_id = _scan(app, tmp_path, 'parsed', _spdx3())
    _, legacy_scan_id = _scan(app, tmp_path, 'legacy', {'@graph': [{'type': 'CreationInfo', 'specVersion': '3.0.1'}]})
    with app.app_context():
        SBOMDocument.create(str(tmp_path / 'parsed-vex.json'), 'parsed-vex.json', parsed_scan_id, format='openvex')
        db.session.remove()
        migration = import_module('src.migrations.versions.cc5359c88dd2_flag_recorded_sbom_dependencies')
        with db.engine.begin() as connection:
            with Operations.context(MigrationContext.configure(connection)):
                migration.downgrade()
                assert 'dependencies_recorded' not in {
                    column['name'] for column in inspect(connection).get_columns('sbom_documents')}
                migration.upgrade()
            flags = connection.execute(text('SELECT source_name, dependencies_recorded FROM sbom_documents')).all()
        assert sorted(flags) == [('legacy.json', 0), ('parsed-vex.json', 1), ('parsed.json', 1)]
