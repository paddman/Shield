from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass(frozen=True, slots=True)
class RetrievedPlaybook:
    name: str
    score: float
    excerpt: str
    content: str


class PlaybookRetriever:
    def __init__(self, playbook_dir: Path) -> None:
        self._playbook_dir = playbook_dir
        self._documents = self._load_documents()
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        if self._documents:
            self._vectorizer = TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                max_features=6000,
                strip_accents="unicode",
            )
            self._matrix = self._vectorizer.fit_transform([doc.content for doc in self._documents])

    def _load_documents(self) -> list[RetrievedPlaybook]:
        if not self._playbook_dir.exists():
            return []
        documents: list[RetrievedPlaybook] = []
        for path in sorted(self._playbook_dir.glob("*.md")):
            content = path.read_text(encoding="utf-8", errors="replace").strip()
            if not content:
                continue
            title = path.stem.replace("-", " ").replace("_", " ").title()
            first_heading = next(
                (line.lstrip("# ").strip() for line in content.splitlines() if line.startswith("#")),
                "",
            )
            documents.append(
                RetrievedPlaybook(
                    name=first_heading or title,
                    score=0.0,
                    excerpt=content[:900],
                    content=content,
                )
            )
        return documents

    def retrieve(self, query: str, top_k: int = 3) -> list[RetrievedPlaybook]:
        if not self._documents or self._vectorizer is None or self._matrix is None:
            return []
        vector = self._vectorizer.transform([query])
        scores = cosine_similarity(vector, self._matrix)[0]
        ranked = sorted(enumerate(scores), key=lambda item: item[1], reverse=True)
        results: list[RetrievedPlaybook] = []
        for index, score in ranked[: max(1, top_k)]:
            if float(score) <= 0:
                continue
            doc = self._documents[index]
            results.append(
                RetrievedPlaybook(
                    name=doc.name,
                    score=round(float(score), 4),
                    excerpt=doc.excerpt,
                    content=doc.content,
                )
            )
        return results
