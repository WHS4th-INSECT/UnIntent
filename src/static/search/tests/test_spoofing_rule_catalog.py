"""Focused regression tests for spoofing effect sink matching."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from src.static.classification.spoofing import match_spoofing_rules
from src.static.classification.spoofing_paths import SpoofingPathAnalyzer
from src.static.model.values import (
    Component,
    EntryPoint,
    EvidenceSource,
    FlowEvidence,
    InstructionIR,
    MethodIR,
    MethodRef,
    Origin,
    UseRole,
)
from src.static.search.api_rules import DEFAULT_RULES
from src.static.search.sinks import scan_sinks


class SpoofingRuleCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.method_ref = MethodRef("Lexample/Worker;", "run", "()V")
        self.component = Component(
            name="example.Entry",
            code_class="example.Entry",
            descriptor="Lexample/Entry;",
            component_type="activity",
            exported=True,
            enabled=True,
            permission=None,
            permission_protection_level=None,
        )
        self.source = EvidenceSource(
            Origin("external_field", field="extra", key="value"),
            UseRole.SENSITIVE_ARGUMENT,
            True,
        )

    def _sites(self, *calls: tuple[str, tuple[int, ...]]):
        method = MethodIR(
            method=self.method_ref,
            access="public",
            instructions=[
                InstructionIR(
                    offset=index * 2,
                    name="invoke-virtual",
                    output="",
                    registers=registers,
                    reference=reference,
                )
                for index, (reference, registers) in enumerate(calls)
            ],
        )
        return scan_sinks({method.method: method}, DEFAULT_RULES)

    def _matches(self, site) -> list[str]:
        flow = FlowEvidence(
            flow_id="test-flow",
            entry_point=EntryPoint(self.component.name, "activity", None),
            sources=[self.source],
            sink=site,
            sink_component=self.component.name,
            nodes=[],
            icc_edges=[],
        )
        return [
            item["rule_id"]
            for item in match_spoofing_rules(
                flow, self.source, {self.component.name: self.component}
            )
        ]

    def test_notification_tracks_payload_not_id_or_tag(self) -> None:
        sites = [
            site
            for site in self._sites(
                (
                    "Landroidx/core/app/NotificationManagerCompat;->notify("
                    "Ljava/lang/String;ILandroid/app/Notification;)V",
                    (0, 1, 2, 3),
                ),
                (
                    "Landroid/app/NotificationManager;->notify("
                    "ILandroid/app/Notification;)V",
                    (0, 1, 2),
                ),
                (
                    "Lexample/Logger;->notify(ILandroid/app/Notification;)V",
                    (0, 1, 2),
                ),
            )
            if site.rule_id == "NOTIFICATION_DISPLAY"
        ]
        self.assertEqual(
            [(site.offset, site.argument_registers) for site in sites],
            [(0, (3,)), (2, (2,))],
        )
        self.assertEqual(self._matches(sites[0]), ["IS_NOTIFICATION_POST"])

    def test_roottools_command_selection_and_classification(self) -> None:
        command = "Lcom/stericson/RootTools/execution/Command;"
        sites = [
            site
            for site in self._sites(
                (
                    "Lcom/stericson/RootTools/execution/Shell;->add("
                    + command + ")" + command,
                    (0, 1),
                ),
                ("Lexample/Logger;->add(" + command + ")V", (0, 1)),
                (
                    "Lcom/stericson/RootTools/execution/Shell;->add("
                    "Ljava/lang/String;)V",
                    (0, 1),
                ),
            )
            if site.rule_id == "SHELL_COMMAND_SUBMISSION"
        ]
        self.assertEqual(
            [(site.offset, site.argument_registers) for site in sites],
            [(0, (1,))],
        )
        self.assertEqual(self._matches(sites[0]), ["IS_SHELL_COMMAND_SUBMISSION"])

    def test_file_write_owner_and_constructor_path_argument(self) -> None:
        sites = [
            site
            for site in self._sites(
                ("Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V", (0, 1)),
                ("Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V", (0, 1)),
                (
                    "Ljava/io/PrintWriter;-><init>("
                    "Ljava/lang/String;Ljava/lang/String;)V",
                    (0, 1, 2),
                ),
            )
            if site.rule_id == "FILE_STREAM_OPEN"
        ]
        self.assertEqual(
            [(site.offset, site.argument_registers) for site in sites],
            [(0, (1,)), (2, (1,)), (4, (1,))],
        )
        self.assertEqual(self._matches(sites[0]), [])
        self.assertEqual(self._matches(sites[1]), ["IS_FILE_WRITE_OPEN"])
        self.assertEqual(self._matches(sites[2]), ["IS_FILE_WRITE_OPEN"])

        # The read-only constructor must not trigger invocation path discovery.
        analyzer = SimpleNamespace(backend=SimpleNamespace(components=[]))
        self.assertEqual(SpoofingPathAnalyzer.augment(analyzer, sites[0], [], None), [])


if __name__ == "__main__":
    unittest.main()
