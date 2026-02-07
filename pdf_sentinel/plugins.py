"""
PDF Sentinel Plugin System
Allows Pro and third-party detectors to register into the analysis pipeline.
"""

from typing import Callable, Dict, List, Any, Optional


class PluginRegistry:
    """
    Registry for analysis plugins. Detectors are callables that receive
    analysis context and return a list of finding dicts.

    Usage::

        registry = PluginRegistry()

        @registry.detector("my_check", stage="post_extract")
        def my_check(ctx):
            # ctx keys: pdf_path, pdf_content, text, results
            return [{"type": "my_finding", "description": "..."}]

        analyzer = PDFAnalyzer(plugins=registry)
        results = analyzer.analyze_pdf("file.pdf")
        # results["my_check"] will contain the plugin's findings
    """

    STAGES = (
        "pre_analysis",     # Before anything runs; ctx has pdf_path only
        "post_decompress",  # After qpdf; ctx adds pdf_content (raw bytes decoded)
        "post_extract",     # After text extraction; ctx adds text + partial results
        "post_analysis",    # After all built-in detectors; ctx has full results
    )

    def __init__(self):
        self._detectors: Dict[str, Dict[str, Any]] = {}

    def detector(
        self,
        name: str,
        stage: str = "post_extract",
        priority: int = 100,
        result_key: Optional[str] = None,
    ) -> Callable:
        """Decorator to register a detector plugin."""
        if stage not in self.STAGES:
            raise ValueError(f"Invalid stage '{stage}'. Must be one of {self.STAGES}")

        def wrapper(fn: Callable) -> Callable:
            self._detectors[name] = {
                "fn": fn,
                "stage": stage,
                "priority": priority,
                "result_key": result_key or name,
            }
            return fn

        return wrapper

    def register(
        self,
        name: str,
        fn: Callable,
        stage: str = "post_extract",
        priority: int = 100,
        result_key: Optional[str] = None,
    ):
        """Imperative registration alternative to the decorator."""
        if stage not in self.STAGES:
            raise ValueError(f"Invalid stage '{stage}'. Must be one of {self.STAGES}")
        self._detectors[name] = {
            "fn": fn,
            "stage": stage,
            "priority": priority,
            "result_key": result_key or name,
        }

    def get_detectors(self, stage: str) -> List[Dict[str, Any]]:
        """Return detectors for a stage, sorted by priority (lower first)."""
        return sorted(
            [d for d in self._detectors.values() if d["stage"] == stage],
            key=lambda d: d["priority"],
        )

    def list_plugins(self) -> List[str]:
        """Return names of all registered plugins."""
        return list(self._detectors.keys())
