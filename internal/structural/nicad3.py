"""NiCad3 clone-detector wrapper.

NiCad3 source: https://github.com/bumper-app/nicad — installed into /opt/nicad
inside the L34 container (see Dockerfile.fingerprint).

NiCad3 is invoked: `nicad <granularity> <language> <systemdir>`
  - granularity: functions | blocks
  - language: c | java | python | cs | go | py | ...
  - systemdir: a directory containing source to analyze

It emits HTML/XML clone reports in <systemdir>_<granularity>-clones/.
We parse the XML for clone-pair entries.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("structural.nicad3")

NICAD_BIN = "/opt/nicad/nicad6"  # NiCad3.x ships an executable historically named nicad6
# fall back to PATH lookup
if not Path(NICAD_BIN).exists():
    found = shutil.which("nicad6") or shutil.which("nicad")
    if found:
        NICAD_BIN = found

# Default similarity threshold for clone class membership (NiCad config).
SIM_THRESHOLD = 70  # percent of identifier-renamed token overlap (Type-3)


@dataclass
class ClonePair:
    file_a: str
    file_b: str
    similarity: int        # percent
    granularity: str       # "functions" | "blocks"
    language: str

    def to_dict(self) -> dict:
        return {
            "file_a": self.file_a,
            "file_b": self.file_b,
            "similarity": self.similarity,
            "granularity": self.granularity,
            "language": self.language,
        }


def _merge_into_one_dir(reference: Path, candidate: Path) -> Path:
    """NiCad scans a single tree. Merge ref + candidate sources into one staged dir
    so cross-tree clones surface."""
    staged = Path(tempfile.mkdtemp(prefix="lw-nicad-"))
    (staged / "reference").mkdir()
    (staged / "candidate").mkdir()
    shutil.copytree(reference, staged / "reference", dirs_exist_ok=True)
    shutil.copytree(candidate, staged / "candidate", dirs_exist_ok=True)
    return staged


def run_nicad(reference: Path, candidate: Path, language: str = "py",
              granularity: str = "functions") -> list[ClonePair]:
    """Run NiCad3 against `reference` + `candidate` jointly. Returns cross-tree pairs."""
    if NICAD_BIN is None:
        log.warning("nicad6 not on PATH — skipping NiCad3 analysis")
        return []

    staged = _merge_into_one_dir(reference, candidate)
    try:
        proc = subprocess.run(
            [NICAD_BIN, granularity, language, str(staged)],
            capture_output=True,
            text=True,
            timeout=900,
        )
        if proc.returncode != 0:
            log.warning("nicad exit %d: %s", proc.returncode, proc.stderr.strip()[:500])
            return []

        # NiCad emits: <staged>_<granularity>-blind-clones-... .xml
        xml_files = list(staged.parent.glob(f"{staged.name}_{granularity}-*-clones-*.xml"))
        if not xml_files:
            xml_files = list(staged.parent.glob(f"{staged.name}*clones*.xml"))
        pairs: list[ClonePair] = []
        for xf in xml_files:
            pairs.extend(_parse_nicad_xml(xf, granularity=granularity, language=language))
        # filter to cross-tree pairs only (one side under reference/, other under candidate/)
        cross = [
            p for p in pairs
            if ("/reference/" in p.file_a and "/candidate/" in p.file_b)
            or ("/candidate/" in p.file_a and "/reference/" in p.file_b)
        ]
        return cross
    finally:
        shutil.rmtree(staged, ignore_errors=True)
        # also clean nicad's adjacent output dirs
        for sib in staged.parent.glob(f"{staged.name}_*"):
            shutil.rmtree(sib, ignore_errors=True)


def _parse_nicad_xml(path: Path, granularity: str, language: str) -> list[ClonePair]:
    """Parse a NiCad XML clones file → list of ClonePair."""
    pairs: list[ClonePair] = []
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        log.warning("xml parse error %s: %s", path, e)
        return pairs

    root = tree.getroot()
    for clone_class in root.iter("class"):
        try:
            sim = int(clone_class.attrib.get("similarity", "0"))
        except ValueError:
            sim = 0
        sources = list(clone_class.iter("source"))
        # emit each cross pair within a class
        for i in range(len(sources)):
            for j in range(i + 1, len(sources)):
                pairs.append(ClonePair(
                    file_a=sources[i].attrib.get("file", ""),
                    file_b=sources[j].attrib.get("file", ""),
                    similarity=sim,
                    granularity=granularity,
                    language=language,
                ))
    return pairs


def has_clone(reference: Path, candidate: Path, language: str = "py",
              min_similarity: int = SIM_THRESHOLD) -> tuple[bool, list[ClonePair]]:
    pairs = run_nicad(reference, candidate, language=language, granularity="functions")
    strong = [p for p in pairs if p.similarity >= min_similarity]
    return (len(strong) > 0, strong)
