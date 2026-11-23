"""Tests for CaptureController and lifecycle management."""

import time
import pytest
from airtrace.capture import CaptureController
from airtrace.interfaces import DEMO_INTERFACE_ID
from airtrace.models import CaptureState


def test_capture_controller_lifecycle():
    controller = CaptureController()
    assert controller.state == CaptureState.IDLE
    assert not controller.is_running

    # Start simulation capture
    started = controller.start_capture(interface=DEMO_INTERFACE_ID)
    assert started is True
    assert controller.is_running
    assert controller.state == CaptureState.CAPTURING

    # Idempotent re-entrancy test: starting again should return False and not crash or spawn a second thread
    duplicate_started = controller.start_capture(interface=DEMO_INTERFACE_ID)
    assert duplicate_started is False

    # Wait for a few packets to be generated
    time.sleep(0.5)

    packets = controller.drain_packets(max_count=100)
    assert len(packets) > 0
    assert packets[0].packet_number >= 1

    # Stop cleanly
    stopped = controller.stop_capture(timeout=2.0)
    assert stopped is True
    assert not controller.is_running
    assert controller.state == CaptureState.IDLE
