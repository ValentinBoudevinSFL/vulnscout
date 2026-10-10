export type VersionEvidence = {
    version: string;
    source: 'sbom' | 'purl' | 'cpe' | 'download';
    identifier: string;
};

export type PackageVersionMetadata = {
    release_version?: string | null;
    source_revision?: string | null;
    version_evidence?: VersionEvidence[];
    version_conflict?: boolean;
    revision_conflict?: boolean;
};

export function asVersionEvidence(value: unknown): VersionEvidence[] {
    if (!value || typeof value !== 'object' || !('version' in value) || !('source' in value)
        || !('identifier' in value) || typeof value.version !== 'string' || typeof value.identifier !== 'string') return [];
    if (value.source !== 'sbom' && value.source !== 'purl' && value.source !== 'cpe' && value.source !== 'download') return [];
    return [{ version: value.version, source: value.source, identifier: value.identifier }];
}

export function releaseVersion(pkg: PackageVersionMetadata & { version: string }): string | null {
    if (pkg.version_conflict) return null;
    return (pkg.release_version !== undefined ? pkg.release_version : pkg.version) || null;
}

export function versionEvidenceTitle(pkg: PackageVersionMetadata): string {
    return (pkg.version_evidence ?? []).map(item => {
        const source = item.source === 'sbom' ? 'SBOM version'
            : item.source === 'download' ? 'Git source URL' : item.source.toUpperCase();
        return `${source}: ${item.version}${item.source === 'sbom' ? '' : ` (${item.identifier})`}`;
    }).join('\n');
}

export function packageVersionLabel(pkg: PackageVersionMetadata & { name: string; version: string }): string {
    const version = pkg.version_conflict ? 'Conflicting metadata' : releaseVersion(pkg) ?? 'Unknown';
    const revision = pkg.revision_conflict ? ' (conflicting revisions)'
        : pkg.source_revision ? ` (${pkg.source_revision.slice(0, 12)})` : '';
    return `${pkg.name}@${version}${revision}`;
}
