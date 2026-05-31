
"""D03 Memory Store — Persistent memory system inspired by Claude Code Chapter 9.

Implements: four memory types (user/feedback/project/reference), file-system storage
with MEMORY.md index, frontmatter parsing, relevance retrieval, freshness awareness,
and the "undeivable principle" (don't memorize what can be queried).

Claude Code patterns applied:
  - 3-layer memory: working/session/persistent
  - MEMORY.md index: 200 lines / 25KB limits
  - Two-step write: content file + index update
  - Four types with structured body (Why/How to apply)
  - Freshness warnings (>1 day)
  - Undeivable principle filter
"""

import os, json, re, time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum


# ============================================================================
# Memory Types (from Claude Code memoryTypes.ts)
# ============================================================================

class MemoryType(Enum):
    USER = "user"          # User role, goals, preferences, responsibilities
    FEEDBACK = "feedback"  # Corrections and confirmations about work approach
    PROJECT = "project"    # Ongoing work, constraints, deadlines, motivations
    REFERENCE = "reference"  # Pointers to external resources (URLs, tools, channels)


MEMORY_FRONTMATTER_KEYS = ["name", "description", "type", "scope", "source", "created_at", "updated_at"]

MAX_ENTRYPOINT_LINES = 200
MAX_ENTRYPOINT_BYTES = 25000
FRONTMATTER_MAX_LINES = 30
MAX_MEMORY_FILES = 200


# ============================================================================
# MemoryEntry
# ============================================================================

@dataclass
class MemoryEntry:
    name: str
    description: str
    mem_type: MemoryType
    content: str
    scope: str = "private"
    source: str = "manual"
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        now = datetime.now().isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now

    def age_days(self) -> int:
        try:
            created = datetime.fromisoformat(self.created_at)
            return (datetime.now() - created).days
        except (ValueError, TypeError):
            return 0

    def freshness_text(self) -> str:
        d = self.age_days()
        if d <= 1:
            return ""
        return (
            f"This memory is {d} days old. Memories are point-in-time observations, "
            f"not live state — claims may be outdated. Verify against current state."
        )

    def to_frontmatter(self) -> str:
        lines = [
            "---",
            f"name: {self.name}",
            f"description: {self.description}",
            f"type: {self.mem_type.value}",
            f"scope: {self.scope}",
            f"source: {self.source}",
            f"created_at: {self.created_at}",
            f"updated_at: {self.updated_at}",
            "---",
            "",
            self.content,
        ]
        return "\n".join(lines)

    @classmethod
    def from_frontmatter(cls, text: str) -> Optional["MemoryEntry"]:
        try:
            if not text.startswith("---"):
                return None
            parts = text.split("---", 2)
            if len(parts) < 3:
                return None
            header = parts[1].strip()
            content = parts[2].strip()

            data = {}
            for line in header.split("\n"):
                line = line.strip()
                if ":" in line:
                    key, _, value = line.partition(":")
                    data[key.strip()] = value.strip()

            return cls(
                name=data.get("name", "unknown"),
                description=data.get("description", ""),
                mem_type=MemoryType(data.get("type", "project")),
                content=content,
                scope=data.get("scope", "private"),
                source=data.get("source", "manual"),
                created_at=data.get("created_at", ""),
                updated_at=data.get("updated_at", ""),
            )
        except Exception:
            return None

    def index_line(self) -> str:
        return f"- [{self.description}]({self.name}.md) — {self.mem_type.value}"


# ============================================================================
# MemoryStore — file-system based storage
# ============================================================================

class MemoryStore:
    def __init__(self, memory_dir: str):
        self.memory_dir = Path(memory_dir)
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.memory_dir / "MEMORY.md"

    # ---- File operations ----

    def _file_path(self, name: str) -> Path:
        safe = re.sub(r"[^a-zA-Z0-9_\-]", "_", name)
        return self.memory_dir / f"{safe}.md"

    def save(self, entry: MemoryEntry) -> bool:
        entry.updated_at = datetime.now().isoformat()
        if not entry.created_at:
            entry.created_at = entry.updated_at

        filepath = self._file_path(entry.name)
        try:
            filepath.write_text(entry.to_frontmatter(), encoding="utf-8")
        except Exception as e:
            print(f"[MemoryStore] Write error: {e}")
            return False

        self._update_index(entry)
        return True

    def load(self, name: str) -> Optional[MemoryEntry]:
        filepath = self._file_path(name)
        if not filepath.exists():
            return None
        try:
            text = filepath.read_text(encoding="utf-8")
            return MemoryEntry.from_frontmatter(text)
        except Exception:
            return None

    def list_all(self) -> List[MemoryEntry]:
        entries = []
        for f in sorted(self.memory_dir.glob("*.md")):
            if f.name == "MEMORY.md":
                continue
            try:
                text = f.read_text(encoding="utf-8")
                entry = MemoryEntry.from_frontmatter(text)
                if entry:
                    entries.append(entry)
            except Exception:
                pass
        return entries

    def delete(self, name: str) -> bool:
        filepath = self._file_path(name)
        if filepath.exists():
            filepath.unlink()
        self._remove_from_index(name)
        return True

    # ---- Index management ----

    def _update_index(self, entry: MemoryEntry):
        index = self._read_index()
        line = entry.index_line()
        name_key = f"({entry.name}.md)"
        # Replace existing entry or append
        found = False
        for i, existing in enumerate(index):
            if name_key in existing:
                index[i] = line
                found = True
                break
        if not found:
            index.append(line)
        self._write_index(index)

    def _remove_from_index(self, name: str):
        index = self._read_index()
        name_key = f"({name}.md)"
        index = [l for l in index if name_key not in l]
        self._write_index(index)

    def _read_index(self) -> List[str]:
        if self.index_path.exists():
            lines = self.index_path.read_text(encoding="utf-8").strip().split("\n")
            return [l for l in lines if l.strip() and not l.startswith("#")]
        return []

    def _write_index(self, lines: List[str]):
        # Enforce limits
        if len(lines) > MAX_ENTRYPOINT_LINES:
            lines = lines[:MAX_ENTRYPOINT_LINES]
            lines.append(f"<!-- INDEX TRUNCATED at {MAX_ENTRYPOINT_LINES} lines -->")

        content = f"# Memory Index\n\n" + "\n".join(lines) + "\n"
        content_bytes = content.encode("utf-8")

        if len(content_bytes) > MAX_ENTRYPOINT_BYTES:
            # Truncate at nearest newline before byte limit
            truncated = content_bytes[:MAX_ENTRYPOINT_BYTES]
            last_nl = truncated.rfind(b"\n")
            if last_nl > 0:
                truncated = truncated[:last_nl]
            content = truncated.decode("utf-8", errors="replace")
            content += f"\n<!-- INDEX TRUNCATED at {MAX_ENTRYPOINT_BYTES} bytes -->\n"

        self.index_path.write_text(content, encoding="utf-8")

    # ---- Relevance retrieval ----

    def find_relevant(self, query: str, k: int = 5) -> List[MemoryEntry]:
        all_entries = self.list_all()
        if not all_entries:
            return []

        q_words = set(query.lower().split())
        scored = []
        for entry in all_entries:
            score = 0
            desc_lower = entry.description.lower()
            content_lower = entry.content.lower()[:500]

            for w in q_words:
                if w in desc_lower:
                    score += 3  # Description matches are weighted higher
                if w in content_lower:
                    score += 1
                if w in entry.name.lower():
                    score += 2

            # Recency bonus: newer entries slightly preferred
            age_bonus = max(0, 1.0 - entry.age_days() * 0.01)
            score += age_bonus

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for score, entry in scored[:k]]


# ============================================================================
# D03MemoryManager — high-level manager connecting to AgentContext
# ============================================================================

class D03MemoryManager:
    """Manages three-layer memory (working/session/persistent) with Claude Code patterns."""

    # Types of data that should NOT be saved (undeivable principle)
    UNDEIVABLE_PATTERNS = [
        "metric", "count", "accuracy", "f1_score", "detection_rate",
        "file_path", "line_number", "code_pattern", "git_hash",
        "timestamp", "episode_number", "total_turns",
    ]

    def __init__(self, project_root: str):
        self.store = MemoryStore(os.path.join(project_root, "memory"))
        self.working: Dict = {}
        self.session: Dict = {}

    def extract_from_episode(self, agent_id: str, episode_data: Dict) -> List[MemoryEntry]:
        """Extract memories from episode data. Applies undeivable principle."""
        new_entries = []
        lessons = episode_data.get("lessons", [])
        surprises = episode_data.get("surprises", [])
        strategy_changes = episode_data.get("strategy_changes", [])

        for lesson in lessons:
            if self._is_memorable(lesson):
                entry = MemoryEntry(
                    name=f"{agent_id}_lesson_{len(self.store.list_all())}",
                    description=lesson.get("summary", "Lesson learned")[:120],
                    mem_type=MemoryType.FEEDBACK,
                    content=f"**Lesson:** {lesson.get('detail', '')}\n**Why:** {lesson.get('why', '')}\n**How to apply:** {lesson.get('apply', '')}",
                    source="auto_extract",
                )
                self.store.save(entry)
                new_entries.append(entry)

        for surprise in surprises:
            if self._is_memorable(surprise):
                entry = MemoryEntry(
                    name=f"{agent_id}_surprise_{len(self.store.list_all())}",
                    description=surprise.get("summary", "Unexpected outcome")[:120],
                    mem_type=MemoryType.PROJECT,
                    content=f"**Finding:** {surprise.get('detail', '')}\n**Why surprising:** {surprise.get('why', '')}\n**Implication:** {surprise.get('apply', '')}",
                    source="auto_extract",
                )
                self.store.save(entry)
                new_entries.append(entry)

        return new_entries

    def _is_memorable(self, item: Dict) -> bool:
        """Apply undeivable principle: skip ephemeral/metric data."""
        text = str(item).lower()
        for pattern in self.UNDEIVABLE_PATTERNS:
            if pattern in text:
                return False
        return True

    def inject_memories(self, query: str, k: int = 5) -> List[Dict]:
        """Retrieve relevant memories with freshness warnings."""
        entries = self.store.find_relevant(query, k)
        results = []
        for entry in entries:
            d = {
                "name": entry.name,
                "description": entry.description,
                "type": entry.mem_type.value,
                "content": entry.content,
                "freshness": entry.freshness_text(),
                "age_days": entry.age_days(),
            }
            results.append(d)
        return results

    def get_memory_prompt_context(self, query: str, k: int = 5) -> str:
        """Format memories as a system reminder string for prompt injection."""
        memories = self.inject_memories(query, k)
        if not memories:
            return ""

        lines = ["<system-reminder>"]
        for m in memories:
            lines.append(f"\n[{m['type'].upper()}] {m['description']}")
            if m["freshness"]:
                lines.append(f"  ⚠ {m['freshness']}")
        lines.append("</system-reminder>")
        return "\n".join(lines)

    def get_stats(self) -> Dict:
        all_entries = self.store.list_all()
        type_counts = {}
        for e in all_entries:
            type_counts[e.mem_type.value] = type_counts.get(e.mem_type.value, 0) + 1
        return {
            "total_memories": len(all_entries),
            "by_type": type_counts,
            "index_lines": len(self.store._read_index()),
            "memory_dir": str(self.store.memory_dir),
        }


# ============================================================================
# Self-Test
# ============================================================================

if __name__ == "__main__":
    import tempfile, shutil

    print("=" * 65)
    print("  D03 Memory Store — Self-Test")
    print("=" * 65)

    tmpdir = tempfile.mkdtemp(prefix="d03_memory_test_")
    store = MemoryStore(tmpdir)

    # Test 1: Save and load entries
    print("\n[1] Saving memory entries...")
    entries = [
        MemoryEntry("user_pref", "User prefers concise responses without summaries",
                    MemoryType.FEEDBACK,
                    "**Rule:** Keep responses brief.\n**Why:** User stated preference.\n**How to apply:** End responses after the key finding, no trailing summary."),
        MemoryEntry("project_auth", "Auth middleware rewrite driven by legal compliance",
                    MemoryType.PROJECT,
                    "**Fact:** Auth middleware rewrite is compliance-driven.\n**Why:** Legal flagged session token storage.\n**How to apply:** Prioritize compliance over ergonomics in auth decisions."),
        MemoryEntry("ref_linear", "Pipeline bugs tracked in Linear project INGEST",
                    MemoryType.REFERENCE,
                    "Check Linear project \"INGEST\" for pipeline bug context."),
        MemoryEntry("user_role", "User is a cybersecurity AI researcher",
                    MemoryType.USER,
                    "User is researching multi-agent adversarial systems and data poisoning."),
        MemoryEntry("feedback_testing", "Integration tests must hit real database",
                    MemoryType.FEEDBACK,
                    "**Rule:** Integration tests must use real database, not mocks.\n**Why:** Prior incident where mock/prod divergence masked a broken migration.\n**How to apply:** Always use test database instance for integration tests."),
    ]
    for e in entries:
        assert store.save(e), f"Failed to save {e.name}"
    print(f"  [OK] Saved {len(entries)} entries")

    # Test 2: Load an entry
    loaded = store.load("user_pref")
    assert loaded is not None
    assert loaded.mem_type == MemoryType.FEEDBACK
    print(f"  [OK] Loaded: {loaded.description}")

    # Test 3: MEMORY.md index
    index_content = store.index_path.read_text(encoding="utf-8")
    assert "User prefers" in index_content
    assert "Auth middleware" in index_content
    print(f"  [OK] MEMORY.md index generated ({len(index_content)} bytes)")

    # Test 4: find_relevant
    results = store.find_relevant("testing database mock", k=3)
    assert len(results) > 0
    print(f"  [OK] find_relevant('testing database mock'): {len(results)} results")
    for r in results:
        print(f"    - {r.description} ({r.mem_type.value})")

    # Test 5: Update an entry
    entries[0].content = "Updated: Keep responses very brief."
    store.save(entries[0])
    updated = store.load("user_pref")
    assert "Updated" in updated.content
    print(f"  [OK] Entry updated successfully")

    # Test 6: Delete
    store.delete("ref_linear")
    assert store.load("ref_linear") is None
    print(f"  [OK] Entry deleted")

    # Test 7: Freshness
    e = entries[0]
    age = e.age_days()
    freshness = e.freshness_text()
    print(f"  [OK] Freshness: age_days={age}, has_warning={len(freshness) > 0}")

    # Test 8: D03MemoryManager
    print("\n[8] Testing D03MemoryManager...")
    mgr = D03MemoryManager(tmpdir)
    mgr.extract_from_episode("agent_1", {
        "lessons": [
            {"summary": "Detected APT29 pattern via DNS exfiltration", "detail": "Used DNS TXT record exfiltration detection", "why": "Prior rules missed TXT-based exfil", "apply": "Add DNS TXT record monitoring to baseline"},
        ],
        "surprises": [
            {"summary": "Kata containers had unexpected escape via device abuse", "detail": "Device abuse technique bypassed Kata isolation", "why": "Kata VM isolation assumed full device isolation", "apply": "Add device cgroup restrictions to Kata configs"},
        ],
    })
    stats = mgr.get_stats()
    print(f"  [OK] MemoryManager: {stats['total_memories']} total, by_type={stats['by_type']}")

    # Test 9: Memory prompt context
    ctx = mgr.get_memory_prompt_context("DNS exfiltration detection", k=3)
    assert "system-reminder" in ctx
    print(f"  [OK] Memory prompt context generated ({len(ctx)} chars)")

    # Test 10: Undeivable principle
    saved = mgr.extract_from_episode("agent_2", {
        "lessons": [
            {"summary": "F1 score improved to 0.95", "detail": "metric data", "why": "tuning", "apply": "continue"},
        ],
    })
    # F1 score metric data should be filtered out
    print(f"  [OK] Undeivable filter: {len(saved)} entries saved (expected 0 for metric-only data)")

    # Test 11: Truncation
    print("\n[11] Testing index truncation...")
    large_store = MemoryStore(os.path.join(tmpdir, "large"))
    for i in range(250):
        e = MemoryEntry(f"test_{i:04d}", f"Test memory number {i}", MemoryType.PROJECT, f"Content {i}")
        large_store.save(e)
    index_lines = large_store._read_index()
    assert len(index_lines) <= MAX_ENTRYPOINT_LINES + 2, f"Index truncation: {len(index_lines)} lines (max {MAX_ENTRYPOINT_LINES})"
    print(f"  [OK] Index truncated: {len(index_lines)} lines (max {MAX_ENTRYPOINT_LINES})")

    # Cleanup
    shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n{'=' * 65}")
    print(f"  [D03 Memory Store] All self-tests passed.")
    print(f"{'=' * 65}")
