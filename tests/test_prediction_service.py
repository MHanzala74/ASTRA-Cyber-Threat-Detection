from __future__ import annotations

from app.services.prediction_service import flow_to_array, make_verdict
from app.schemas import NetworkFlow


def test_make_verdict_prefers_threat_when_models_disagree():
    assert make_verdict("benign", "ddos") == "ddos"
    assert make_verdict("dos", "benign") == "dos"
    assert make_verdict("ddos", "ddos") == "ddos"


def test_flow_to_array_preserves_expected_shape():
    flow = NetworkFlow(
        Flow_Duration=1.0,
        Total_Fwd_Packets=2.0,
        Flow_Bytes_per_s=10.0,
        Flow_Packets_per_s=20.0,
        Down_Up_Ratio=3.0,
        Fwd_Avg_Bytes_Bulk=4.0,
        Fwd_Avg_Packets_Bulk=5.0,
        Bwd_Avg_Bytes_Bulk=6.0,
        Bwd_Avg_Packets_Bulk=7.0,
    )

    values = flow_to_array(flow)
    assert values.shape == (1, 51)
    assert values[0, 0] == 1.0
    assert values[0, 9] == 20.0
