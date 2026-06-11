import sys, subprocess, json, tempfile
from pathlib import Path

root = Path('uploads/session_2_multilang/extracted')
rules = str(Path('app/rules/expanded-semgrep.yaml'))

# Resolve semgrep exe the same way sast_scanner now does
scripts_dir = Path(sys.executable).parent
semgrep_exe = None
for name in ('semgrep.exe', 'semgrep'):
    candidate = scripts_dir / name
    if candidate.exists():
        semgrep_exe = str(candidate)
        break
semgrep_exe = semgrep_exe or 'semgrep'
print('Semgrep exe:', semgrep_exe)

with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as tmp:
    output_file = tmp.name

proc = subprocess.run(
    [semgrep_exe, '--config', rules, '--json', '--quiet', '--output', output_file, str(root)],
    capture_output=True, text=True, timeout=60
)
print('Return code:', proc.returncode)
if proc.stderr:
    print('STDERR:', proc.stderr[:300])

out = Path(output_file)
if out.exists() and out.stat().st_size > 0:
    data = json.loads(out.read_text())
    results = data.get('results', [])
    print(f'Semgrep findings: {len(results)}')
    for r in results:
        sev = r['extra']['severity']
        path = r['path']
        rule = r['check_id']
        print(f'  [{sev}] {path} -- {rule}')
else:
    print('No output or empty')
