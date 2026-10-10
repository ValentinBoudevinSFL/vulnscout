import { asVersionEvidence, packageVersionLabel, releaseVersion, versionEvidenceTitle } from '../../src/helpers/packageVersions';

test('release display respects unknown/conflicting metadata and supports older API rows', () => {
    expect(releaseVersion({version: '1.0'})).toBe('1.0');
    expect(releaseVersion({version: ''})).toBeNull();
    expect(releaseVersion({version: 'a'.repeat(40), release_version: null})).toBeNull();
    expect(releaseVersion({version: '1.0', version_conflict: true})).toBeNull();
});

test('evidence guards malformed API entries', () => {
    for (const value of [null, 1, {}, {version: 1, source: 'purl', identifier: 'pkg:generic/lib@1'},
        {version: '1', source: 'bad', identifier: 'pkg:generic/lib@1'}, {version: '1', source: 'purl'},
        {version: '1', source: 'purl', identifier: 1}]) {
        expect(asVersionEvidence(value)).toEqual([]);
    }
    expect(asVersionEvidence({version: '1', source: 'cpe', identifier: 'cpe:...'})).toHaveLength(1);
    expect(asVersionEvidence({version: '1', source: 'sbom', identifier: '1'})).toHaveLength(1);
});

test('dependency labels show releases and shortened revisions without changing IDs', () => {
    expect(packageVersionLabel({name: 'lib', version: '1.0'})).toBe('lib@1.0');
    expect(packageVersionLabel({name: 'lib', version: 'a'.repeat(40), release_version: '1.0',
        source_revision: 'a'.repeat(40)})).toBe('lib@1.0 (aaaaaaaaaaaa)');
    expect(packageVersionLabel({name: 'lib', version: '', release_version: null})).toBe('lib@Unknown');
    expect(packageVersionLabel({name: 'lib', version: '1.0', version_conflict: true,
        revision_conflict: true})).toBe('lib@Conflicting metadata (conflicting revisions)');
});

test('evidence titles retain the original values and identifiers', () => {
    expect(versionEvidenceTitle({})).toBe('');
    expect(versionEvidenceTitle({version_evidence: [
        {source: 'sbom', version: 'a'.repeat(40), identifier: 'a'.repeat(40)},
        {source: 'purl', version: 'v1.0', identifier: 'pkg:generic/lib@v1.0'},
        {source: 'cpe', version: '1.0', identifier: 'cpe:...'},
    ]})).toBe(`SBOM version: ${'a'.repeat(40)}\nPURL: v1.0 (pkg:generic/lib@v1.0)\nCPE: 1.0 (cpe:...)`);
});
