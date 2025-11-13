import base64
import binascii
import json
import math
import mimetypes
import os
import re
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

try:
    import magic  # type: ignore
except ImportError:  # pragma: no cover
    magic = None  # type: ignore

try:
    from PIL import Image  # type: ignore
    from PIL.ExifTags import TAGS as EXIF_TAGS  # type: ignore
except ImportError:  # pragma: no cover
    Image = None  # type: ignore
    EXIF_TAGS: Dict[int, str] = {}


EICAR_SIGNATURE = b"X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
BASE64_HEUR_RE = re.compile(rb'(?:[A-Za-z0-9+/]{80,})(?:={0,2})')
URL_HEUR_RE = re.compile(rb'https?://[^\s]{12,}', re.IGNORECASE)

SUSPICIOUS_BYTE_TERMS = [
    b'powershell', b'-enc', b'-encodedcommand', b'invoke-mimikatz', b'invoke-expression',
    b'certutil', b'bitsadmin', b'wscript.shell', b'createobject(\"wscript.shell\"',
    b'rundll32', b'regsvr32', b'mshta', b'cmd.exe /c', b'cmd /c', b'net user', b'net localgroup',
    b'add-mppreference', b'schtasks', b'ftp -s', b'payload', b'mimikatz', b'spwnshell',
    b'virtualalloc', b'writeprocessmemory', b'createprocess', b'createremotethread',
    b'::set shell=', b'exec(', b'eval(', b'base64.b64decode(', b'import socket', b'socket.socket',
    b'webclient.downloadstring', b'webclient.downloadfile'
]

SUSPICIOUS_TEXT_TERMS = [
    'invoke-mimikatz', 'powershell -enc', 'powershell.exe -enc',
    'new-object net.webclient', 'downloadstring', 'downloadfile', 'invoke-expression',
    'from ctypes import', 'subprocess.Popen', 'subprocess.call', 'os.system',
    'base64.b64decode(', 'requests.post(', 'requests.get(', 'add_mppreference',
    'document_open', 'autoopen', 'workbook_open', 'shell('
]

SUSPICIOUS_ARCHIVE_EXTS = (
    '.ps1', '.vbs', '.vbe', '.js', '.jse', '.bat', '.cmd', '.hta', '.lnk',
    '.wsf', '.exe', '.dll', '.scr', '.msi', '.jar', '.reg'
)

MACRO_INDICATOR_FILENAMES = (
    'vbaproject.bin', 'word/vba', 'xl/vba', 'ppt/vba', 'macros/', 'macro/',
    'word/_rels', 'xl/_rels', 'ppt/_rels'
)

FILE_TYPE_MAP: Dict[str, Dict[str, Set[str]]] = {
    'executables': {
        'extensions': {'.exe', '.dll'},
        'mime_types': {'application/x-dosexec', 'application/vnd.microsoft.portable-executable'}
    },
    'scripts': {
        'extensions': {'.ps1', '.js', '.vbs', '.vbe', '.bat', '.cmd', '.sh'},
        'mime_types': {'text/x-python', 'text/x-shellscript', 'application/x-javascript'}
    },
    'documents': {
        'extensions': {
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.json', '.xml'
        },
        'mime_types': {
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/json',
            'application/xml',
            'text/xml'
        }
    },
    'archives': {
        'extensions': {'.zip', '.tar', '.gz', '.tar.gz', '.tgz'},
        'mime_types': {
            'application/zip',
            'application/x-tar',
            'application/gzip',
            'application/x-gtar'
        }
    },
    'images': {
        'extensions': {'.png', '.jpg', '.jpeg', '.gif'},
        'mime_prefixes': {'image/'}
    }
}

DEFAULT_CATEGORY = 'documents'


@dataclass
class ScanResult:
    file_type: str
    mime_type: str
    size: int
    yara_hits: List[str] = field(default_factory=list)
    heuristics: List[str] = field(default_factory=list)
    analysis_notes: List[str] = field(default_factory=list)
    scan_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)
    inner_hits: List[Dict[str, object]] = field(default_factory=list)
    verdict: str = 'clean'

    def to_dict(self) -> Dict[str, object]:
        out = {
            'file_type': self.file_type,
            'mime_type': self.mime_type,
            'size': self.size,
            'yara_hits': self.yara_hits,
            'heuristics': self.heuristics,
            'analysis_notes': self.analysis_notes,
            'scan_steps': self.scan_steps,
            'metadata': self.metadata,
            'inner_hits': self.inner_hits,
            'verdict': self.verdict
        }
        return out


def detect_mime(path: str) -> str:
    mime = None
    if magic is not None:
        try:
            mime = magic.from_file(path, mime=True)  # type: ignore[attr-defined]
        except Exception:
            mime = None
    if not mime:
        mime, _ = mimetypes.guess_type(path)
    return mime or 'application/octet-stream'


def _normalize_extension(path: str) -> str:
    lower_name = Path(path).name.lower()
    if lower_name.endswith('.tar.gz'):
        return '.tar.gz'
    if lower_name.endswith('.tgz'):
        return '.tgz'
    return Path(lower_name).suffix


def classify_file(path: str, mime_type: str) -> str:
    ext = _normalize_extension(path)
    for category, rules in FILE_TYPE_MAP.items():
        if ext and ext in rules.get('extensions', set()):
            return category
        mime_matches = rules.get('mime_types', set())
        if mime_type and mime_type in mime_matches:
            return category
        prefixes = rules.get('mime_prefixes', set())
        if mime_type and any(mime_type.startswith(prefix) for prefix in prefixes):
            return category
    return DEFAULT_CATEGORY if ext in FILE_TYPE_MAP.get(DEFAULT_CATEGORY, {}).get('extensions', set()) else 'unknown'


def analyze_buffer(buf: bytes, context_label: str, allow_entropy: bool = True) -> Set[str]:
    findings: Set[str] = set()
    if not buf:
        return findings

    upper = buf.upper()
    if EICAR_SIGNATURE in upper:
        findings.add(f'{context_label}: EICAR signature detected')

    lower = buf.lower()

    for term in SUSPICIOUS_BYTE_TERMS:
        if term in lower:
            try:
                term_str = term.decode('utf-8', errors='ignore')
            except Exception:
                term_str = str(term)
            findings.add(f'{context_label}: contains "{term_str}"')

    base64_matches = BASE64_HEUR_RE.findall(buf)
    if base64_matches:
        total_b64 = sum(len(m) for m in base64_matches)
        if total_b64 > 200:
            findings.add(f'{context_label}: large Base64 payload detected ({len(base64_matches)} matches)')

    url_matches = URL_HEUR_RE.findall(buf)
    if url_matches:
        execution_indicators = [b'powershell', b'cmd.exe', b'curl', b'wget', b'bitsadmin', b'requests', b'iex', b'invoke-webrequest']
        if any(ind in lower for ind in execution_indicators):
            findings.add(f'{context_label}: embedded URL with execution tooling ({len(url_matches)} URLs found)')
        elif len(url_matches) > 5:
            findings.add(f'{context_label}: multiple embedded URLs detected ({len(url_matches)} URLs)')

    text = ''
    try:
        text = buf.decode('utf-8', errors='ignore').lower()
    except Exception:
        try:
            text = buf.decode('latin-1', errors='ignore').lower()
        except Exception:
            text = ''

    if text:
        for phrase in SUSPICIOUS_TEXT_TERMS:
            if phrase.lower() in text:
                findings.add(f'{context_label}: contains "{phrase}"')

        if 'shellcode' in text or 'payload' in text:
            findings.add(f'{context_label}: contains shellcode/payload references')

        if text.count('\\x') > 10 or text.count('\\u') > 10:
            findings.add(f'{context_label}: potential obfuscated code detected')

        for func in ['eval(', 'exec(', 'compile(', '__import__', 'getattr(', 'setattr(']:
            if func in text:
                findings.add(f'{context_label}: contains dangerous function call "{func}"')

    if allow_entropy and len(buf) > 100:
        try:
            byte_freq: Dict[int, int] = {}
            for byte in buf:
                byte_freq[byte] = byte_freq.get(byte, 0) + 1
            entropy = -sum((freq / len(buf)) * math.log2(freq / len(buf)) for freq in byte_freq.values() if freq > 0)
            if entropy > 7.5:
                findings.add(f'{context_label}: high entropy detected (potential encryption/compression)')
        except Exception:
            pass

    return findings


class FileScanner:
    def __init__(
        self,
        yara_scanner,
        max_archive_items: int = 25,
        max_archive_depth: int = 1,
        max_inner_file_bytes: int = 256_000
    ):
        self.yara_scanner = yara_scanner
        self.max_archive_items = max_archive_items
        self.max_archive_depth = max_archive_depth
        self.max_inner_file_bytes = max_inner_file_bytes
        self.primary_read_size = 2 * 1024 * 1024

    def scan(self, path: str, depth: int = 0) -> ScanResult:
        size = 0
        try:
            size = os.path.getsize(path)
        except Exception:
            size = 0

        mime_type = detect_mime(path)
        file_type = classify_file(path, mime_type)
        result = ScanResult(file_type=file_type, mime_type=mime_type, size=size)
        result.scan_steps.append('mime_detection')

        if file_type == 'executables':
            self._scan_executable(path, result)
        elif file_type == 'scripts':
            self._scan_script(path, result)
        elif file_type == 'archives':
            self._scan_archive(path, result, depth)
        elif file_type == 'images':
            self._scan_image(path, result)
        elif file_type == 'documents':
            self._scan_document(path, result)
        else:
            self._scan_generic(path, result)

        if result.yara_hits or result.heuristics or result.inner_hits:
            result.verdict = 'suspicious'
        else:
            result.verdict = 'clean'

        result.heuristics = sorted(set(result.heuristics))
        result.yara_hits = sorted(set(result.yara_hits))
        return result

    # Scan helpers ---------------------------------------------------------

    def _run_yara(self, path: str, result: ScanResult) -> List[str]:
        hits: List[str] = []
        try:
            matches = self.yara_scanner.scan_file(path)
            if matches:
                if isinstance(matches, list):
                    hits.extend(matches)
                else:
                    hits.append(str(matches))
        except Exception as exc:
            result.analysis_notes.append(f'YARA scan error: {exc}')
        return hits

    def _read_chunks(self, path: str) -> List[bytes]:
        chunks: List[bytes] = []
        try:
            file_size = os.path.getsize(path)
        except Exception:
            file_size = 0
        try:
            with open(path, 'rb') as fh:
                primary = fh.read(self.primary_read_size if file_size <= 0 else min(self.primary_read_size, file_size))
                if primary:
                    chunks.append(primary)
                if file_size > 1024 * 1024:
                    mid_pos = file_size // 2
                    fh.seek(max(0, mid_pos - 51_200), 0)
                    mid_chunk = fh.read(102_400)
                    if mid_chunk:
                        chunks.append(mid_chunk)
                    fh.seek(max(0, file_size - 102_400), 0)
                    end_chunk = fh.read(102_400)
                    if end_chunk:
                        chunks.append(end_chunk)
        except Exception:
            pass
        return chunks

    def _run_heuristics(self, path: str, context_label: str, allow_entropy: bool, result: ScanResult) -> List[str]:
        heuristics: Set[str] = set()
        chunks = self._read_chunks(path)
        for idx, chunk in enumerate(chunks):
            label = context_label if idx == 0 else f'{context_label}:segment{idx}'
            heuristics.update(analyze_buffer(chunk, label, allow_entropy=allow_entropy))
        if not chunks:
            result.analysis_notes.append(f'Heuristic scan skipped: unable to read data for {context_label}')
        return sorted(heuristics)

    # Category specific scanning ------------------------------------------

    def _scan_executable(self, path: str, result: ScanResult):
        result.scan_steps.extend(['yara', 'heuristics'])
        result.yara_hits.extend(self._run_yara(path, result))
        result.heuristics.extend(self._run_heuristics(path, 'file', allow_entropy=True, result=result))

    def _scan_script(self, path: str, result: ScanResult):
        result.scan_steps.extend(['yara', 'decode', 'heuristics'])
        result.yara_hits.extend(self._run_yara(path, result))
        decoded_findings = self._decode_script_layers(path, result)
        if decoded_findings:
            result.heuristics.extend(decoded_findings)
        result.heuristics.extend(self._run_heuristics(path, 'script', allow_entropy=True, result=result))

    def _scan_document(self, path: str, result: ScanResult):
        result.scan_steps.extend(['document_analysis'])
        ext = _normalize_extension(path)
        if ext == '.pdf':
            result.analysis_notes.extend(self._scan_pdf(path))
        elif ext in {'.docx', '.pptx', '.xlsx', '.doc', '.ppt', '.xls'}:
            result.analysis_notes.extend(self._scan_office_document(path))
        elif ext == '.json':
            result.analysis_notes.extend(self._scan_json(path))
        elif ext == '.xml':
            result.analysis_notes.extend(self._scan_xml(path))
        else:
            result.analysis_notes.append(f'No specialised document parser for {ext or "unknown extension"}')

        # Apply limited heuristics (no entropy checks)
        result.scan_steps.append('heuristics')
        result.heuristics.extend(self._run_heuristics(path, 'document', allow_entropy=False, result=result))

    def _scan_archive(self, path: str, result: ScanResult, depth: int):
        result.scan_steps.append('archive_listing')
        entries: List[Dict[str, object]] = []
        suspicious_children: List[Dict[str, object]] = []

        # Try ZIP first
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as zf, tempfile.TemporaryDirectory() as tmpdir:
                    for idx, info in enumerate(zf.infolist()):
                        if idx >= self.max_archive_items:
                            result.analysis_notes.append('Archive inspection truncated after max entries')
                            break
                        entry = {
                            'name': info.filename,
                            'size': info.file_size,
                            'is_dir': info.is_dir()
                        }
                        entries.append(entry)
                        if not info.is_dir():
                            lower_name = info.filename.lower()
                            if any(ind in lower_name for ind in MACRO_INDICATOR_FILENAMES):
                                result.heuristics.append(f'archive entry "{info.filename}" indicates potential Office macro payload')
                            if lower_name.endswith(SUSPICIOUS_ARCHIVE_EXTS):
                                result.heuristics.append(f'archive contains potentially dangerous file type: {info.filename}')
                            if depth < self.max_archive_depth and info.file_size <= self.max_inner_file_bytes:
                                data = zf.read(info.filename)
                                child_path = Path(tmpdir) / f'{idx}_{Path(info.filename).name}'
                                try:
                                    child_path.write_bytes(data)
                                    child_result = self.scan(str(child_path), depth + 1)
                                    entry['child_verdict'] = child_result.verdict
                                    entry['child_yara'] = child_result.yara_hits
                                    entry['child_heuristics'] = child_result.heuristics
                                    if child_result.verdict == 'suspicious':
                                        suspicious_children.append({
                                            'name': info.filename,
                                            'verdict': child_result.verdict,
                                            'yara': child_result.yara_hits,
                                            'heuristics': child_result.heuristics
                                        })
                                except Exception as exc:
                                    result.analysis_notes.append(f'Failed to analyse archive entry {info.filename}: {exc}')
            except Exception as exc:
                result.analysis_notes.append(f'Archive inspection failed: {exc}')
        else:
            # Try TAR (including tar.gz)
            try:
                with tarfile.open(path, 'r:*') as tf, tempfile.TemporaryDirectory() as tmpdir:
                    members = [m for m in tf.getmembers() if m.isfile()]
                    for idx, member in enumerate(members):
                        if idx >= self.max_archive_items:
                            result.analysis_notes.append('Archive inspection truncated after max entries')
                            break
                        entry = {'name': member.name, 'size': member.size, 'is_dir': False}
                        entries.append(entry)
                        lower_name = member.name.lower()
                        if any(ind in lower_name for ind in MACRO_INDICATOR_FILENAMES):
                            result.heuristics.append(f'archive entry \"{member.name}\" indicates potential Office macro payload')
                        if lower_name.endswith(SUSPICIOUS_ARCHIVE_EXTS):
                            result.heuristics.append(f'archive contains potentially dangerous file type: {member.name}')
                        if depth < self.max_archive_depth and member.size <= self.max_inner_file_bytes:
                            try:
                                extracted = tf.extractfile(member)
                                if extracted:
                                    data = extracted.read()
                                    child_path = Path(tmpdir) / f'{idx}_{Path(member.name).name}'
                                    child_path.write_bytes(data)
                                    child_result = self.scan(str(child_path), depth + 1)
                                    entry['child_verdict'] = child_result.verdict
                                    entry['child_yara'] = child_result.yara_hits
                                    entry['child_heuristics'] = child_result.heuristics
                                    if child_result.verdict == 'suspicious':
                                        suspicious_children.append({
                                            'name': member.name,
                                            'verdict': child_result.verdict,
                                            'yara': child_result.yara_hits,
                                            'heuristics': child_result.heuristics
                                        })
                            except Exception as exc:
                                result.analysis_notes.append(f'Failed to analyse archive member {member.name}: {exc}')
            except tarfile.TarError:
                result.analysis_notes.append('Archive format not recognised (not ZIP/TAR)')
            except Exception as exc:
                result.analysis_notes.append(f'Archive inspection failed: {exc}')

        result.metadata['entries'] = entries
        if suspicious_children:
            result.inner_hits.extend(suspicious_children)

    def _scan_image(self, path: str, result: ScanResult):
        result.scan_steps.append('exif_metadata')
        if Image is None:
            result.analysis_notes.append('Pillow not installed; EXIF extraction unavailable')
            return
        try:
            with Image.open(path) as img:
                exif = img.getexif()
                if exif:
                    metadata = {}
                    for tag_id, value in exif.items():
                        tag = EXIF_TAGS.get(tag_id, tag_id)
                        metadata[str(tag)] = value
                    result.metadata['exif'] = metadata
                else:
                    result.analysis_notes.append('No EXIF metadata present')
        except Exception as exc:
            result.analysis_notes.append(f'EXIF extraction failed: {exc}')

    def _scan_generic(self, path: str, result: ScanResult):
        result.scan_steps.extend(['yara', 'heuristics'])
        result.yara_hits.extend(self._run_yara(path, result))
        result.heuristics.extend(self._run_heuristics(path, 'file', allow_entropy=False, result=result))

    # Detailed document helpers -------------------------------------------

    def _scan_pdf(self, path: str) -> List[str]:
        notes: List[str] = []
        try:
            with open(path, 'rb') as fh:
                head = fh.read(8192).lower()
            if b'%pdf' not in head:
                notes.append('PDF header not detected; file may be malformed')
            for indicator in [b'/js', b'/javascript', b'/aa', b'/openaction']:
                if indicator in head:
                    notes.append('Possible active content indicator detected in PDF header')
        except Exception as exc:
            notes.append(f'Failed to inspect PDF header: {exc}')
        return notes

    def _scan_office_document(self, path: str) -> List[str]:
        notes: List[str] = []
        try:
            with zipfile.ZipFile(path) as zf:
                macro_hits = []
                rel_hits = []
                for info in zf.infolist():
                    lower_name = info.filename.lower()
                    if any(ind in lower_name for ind in MACRO_INDICATOR_FILENAMES):
                        macro_hits.append(info.filename)
                    if lower_name.endswith('.rels'):
                        rel_hits.append(info.filename)
                if macro_hits:
                    notes.append(f'Potential macro-containing entries: {", ".join(macro_hits[:5])}')
                else:
                    notes.append('No obvious macro indicators found')
                if rel_hits:
                    notes.append(f'Relationship files present ({len(rel_hits)} entries)')
        except zipfile.BadZipFile:
            notes.append('Office document structure invalid (not a valid ZIP container)')
        except Exception as exc:
            notes.append(f'Failed to inspect Office document: {exc}')
        return notes

    def _scan_json(self, path: str) -> List[str]:
        notes: List[str] = []
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                json.load(fh)
            notes.append('JSON parsed successfully')
        except json.JSONDecodeError as exc:
            notes.append(f'JSON parsing failed: {exc}')
        except Exception as exc:
            notes.append(f'JSON inspection error: {exc}')
        return notes

    def _scan_xml(self, path: str) -> List[str]:
        notes: List[str] = []
        try:
            import xml.etree.ElementTree as ET

            ET.parse(path)
            notes.append('XML parsed successfully')
        except ET.ParseError as exc:
            notes.append(f'XML parsing failed: {exc}')
        except Exception as exc:
            notes.append(f'XML inspection error: {exc}')
        return notes

    def _decode_script_layers(self, path: str, result: ScanResult) -> List[str]:
        findings: Set[str] = set()
        try:
            with open(path, 'rb') as fh:
                data = fh.read(self.primary_read_size)
            matches = BASE64_HEUR_RE.findall(data)
            for idx, match in enumerate(matches[:3]):
                try:
                    decoded = base64.b64decode(match, validate=True)
                    findings.update(analyze_buffer(decoded, f'script:decoded_layer{idx}', allow_entropy=False))
                    result.analysis_notes.append(f'Decoded potential base64 layer ({len(decoded)} bytes)')
                except (binascii.Error, ValueError):
                    continue
        except Exception as exc:
            result.analysis_notes.append(f'Failed to decode script layers: {exc}')
        return sorted(findings)

