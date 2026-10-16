"""Shared test data: the 2030.5 namespace, the keys pinned for agent 3.2.50, a ReadingType
builder, and the client identity the fake meter accepts."""

from __future__ import annotations

import time

from aio2030dot5 import Identity, ReadingType, load_identity
from aio2030dot5.models import parse_xml

from .conftest import Pki
from .meter_server import FixtureTree

NS = "urn:ieee:std:2030.5:ns"


def rt(**fields: int) -> ReadingType:
    body = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return ReadingType.from_xml(parse_xml(f'<ReadingType xmlns="{NS}">{body}</ReadingType>'))


PINNED_KEYS_3_2_50 = [
    "power",
    "energy_summation_received",
    "energy_summation_delivered",
    "apparent_energy_summation_received",
    "apparent_energy_summation_delivered",
    "reactive_energy_summation_received",
    "reactive_energy_summation_delivered",
    "energy_tou_summation_received",
    "energy_tou_summation_delivered",
    "energy_interval_net",
    "energy_interval_received",
    "energy_interval_delivered",
    "apparent_energy_interval_received",
    "apparent_energy_interval_delivered",
    "reactive_energy_interval_received",
    "reactive_energy_interval_delivered",
    "power_maximum_received",
    "power_maximum_delivered",
    "power_factor",
    "power_factor_phase_a",
    "power_factor_phase_b",
    "power_factor_phase_c",
]


def registered(pki: Pki) -> Identity:
    return load_identity(pki.client_cert.read_text(), pki.client_key.read_text())


class SlowTree(FixtureTree):
    """Answers requests whose target contains "slow" after 0.5 s."""

    def respond(self, target: str) -> tuple[int, str]:
        if "slow" in target:
            time.sleep(0.5)
        return super().respond(target)
