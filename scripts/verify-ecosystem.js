'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const [vespdexPath, asphdexRoot, bansheePath] = process.argv.slice(2);
if (!vespdexPath || !asphdexRoot || !bansheePath) {
    console.error('Usage: node scripts/verify-ecosystem.js <vespdex executable> <AsphDex checkout> <banshee executable>');
    process.exit(2);
}

const vespdex = path.resolve(vespdexPath);
const asphdex = path.resolve(asphdexRoot);
const banshee = path.resolve(bansheePath);
const { inspect } = require(path.join(asphdex, 'js', 'behavior-report.js'));
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'vespdex ecosystem '));
const sample = path.join(work, 'benign.txt');
const capture = path.join(work, 'capture.json');
const reportPath = path.join(work, 'report.json');

function digest(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
}

function run(executable, args) {
    return execFileSync(executable, args, {
        cwd: work, timeout: 45000, maxBuffer: 8 * 1024 * 1024, windowsHide: true
    });
}

try {
    const benign = Buffer.from('VespDex benign interoperability fixture.\n');
    fs.writeFileSync(sample, benign);
    const staticReport = JSON.parse(run(process.execPath, [
        path.join(asphdex, 'bin', 'asphdex.js'), 'analyze', '--json',
        '--engine', 'js', '--privacy', sample
    ]));
    const sha = digest(benign);
    assert.equal(staticReport.hashes.sha256.toLowerCase(), sha);
    fs.writeFileSync(capture, JSON.stringify({
        schemaVersion: 1, caseId: 'ecosystem-001', sampleSha256: sha, source: 'synthetic-ecosystem',
        events: [
            { timestamp: '2026-11-21T10:00:02Z', kind: 'network-connection', detail: '192.0.2.1' },
            { timestamp: '2026-11-21T10:00:00Z', kind: 'file-write', detail: 'ignored.example.org' },
            { timestamp: '2026-11-21T10:00:01Z', kind: 'dns-query', detail: 'example.org' }
        ]
    }));

    const bytes = run(vespdex, [capture]);
    fs.writeFileSync(reportPath, bytes);
    const parsed = JSON.parse(bytes);
    assert.equal(parsed.tool, 'vespdex');
    assert.equal(parsed.sampleSha256, sha);
    const summary = inspect(bytes, staticReport.hashes.sha256);
    assert.equal(summary.eventCount, 3);
    assert.equal(inspect(bytes, digest('different benign file')), null);

    const indicators = JSON.parse(run(banshee, ['behavior', reportPath]));
    assert.equal(indicators.sample_sha256, sha);
    assert.equal(indicators.event_count, 3);
    assert.deepEqual(
        indicators.observables.iocs.map(ioc => [ioc.value, ioc.first_line]).sort(),
        [['192.0.2.1', 3], ['example.org', 2]]
    );

    console.log(JSON.stringify({
        report_format: parsed.schemaVersion,
        asphdex_matching_hash: true,
        asphdex_rejected_other_hash: true,
        banshee_network_indicators: indicators.observables.iocs.length,
        ignored_non_network_detail: true
    }, null, 2));
} finally {
    for (const file of [sample, capture, reportPath]) {
        if (fs.existsSync(file)) fs.unlinkSync(file);
    }
    fs.rmdirSync(work);
}
