"""
ASTRA - Pydantic Schemas
Request and response models for all API endpoints.
"""

from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel, Field


# ══════════════════════════════════════════════════════════════════════
#  REQUEST — single network flow
# ══════════════════════════════════════════════════════════════════════
class NetworkFlow(BaseModel):
    """
    51-feature network flow record extracted by a flow analyzer (e.g. CICFlowMeter).
    Missing fields default to 0.0.
    """
    Flow_Duration:                  float = 0.0
    Total_Fwd_Packets:              float = 0.0
    Total_Length_of_Fwd_Packets:    float = 0.0
    Fwd_Packet_Length_Max:          float = 0.0
    Fwd_Packet_Length_Min:          float = 0.0
    Fwd_Packet_Length_Mean:         float = 0.0
    Bwd_Packet_Length_Max:          float = 0.0
    Bwd_Packet_Length_Min:          float = 0.0
    Flow_Bytes_per_s:               float = Field(0.0, alias="Flow_Bytes/s")
    Flow_Packets_per_s:             float = Field(0.0, alias="Flow_Packets/s")
    Flow_IAT_Mean:                  float = 0.0
    Flow_IAT_Std:                   float = 0.0
    Flow_IAT_Max:                   float = 0.0
    Flow_IAT_Min:                   float = 0.0
    Fwd_IAT_Mean:                   float = 0.0
    Fwd_IAT_Std:                    float = 0.0
    Fwd_IAT_Min:                    float = 0.0
    Bwd_IAT_Total:                  float = 0.0
    Bwd_IAT_Mean:                   float = 0.0
    Bwd_IAT_Std:                    float = 0.0
    Bwd_IAT_Max:                    float = 0.0
    Bwd_IAT_Min:                    float = 0.0
    Fwd_PSH_Flags:                  float = 0.0
    Fwd_Header_Length:              float = 0.0
    Bwd_Header_Length:              float = 0.0
    Bwd_Packets_per_s:              float = Field(0.0, alias="Bwd_Packets/s")
    Min_Packet_Length:              float = 0.0
    Max_Packet_Length:              float = 0.0
    Packet_Length_Mean:             float = 0.0
    Packet_Length_Variance:         float = 0.0
    FIN_Flag_Count:                 float = 0.0
    RST_Flag_Count:                 float = 0.0
    PSH_Flag_Count:                 float = 0.0
    ACK_Flag_Count:                 float = 0.0
    URG_Flag_Count:                 float = 0.0
    Down_Up_Ratio:                  float = Field(0.0, alias="Down/Up_Ratio")
    Fwd_Avg_Bytes_Bulk:             float = Field(0.0, alias="Fwd_Avg_Bytes/Bulk")
    Fwd_Avg_Packets_Bulk:           float = Field(0.0, alias="Fwd_Avg_Packets/Bulk")
    Fwd_Avg_Bulk_Rate:              float = 0.0
    Bwd_Avg_Bytes_Bulk:             float = Field(0.0, alias="Bwd_Avg_Bytes/Bulk")
    Bwd_Avg_Packets_Bulk:           float = Field(0.0, alias="Bwd_Avg_Packets/Bulk")
    Bwd_Avg_Bulk_Rate:              float = 0.0
    Init_Win_bytes_forward:         float = 0.0
    Init_Win_bytes_backward:        float = 0.0
    act_data_pkt_fwd:               float = 0.0
    min_seg_size_forward:           float = 0.0
    Active_Mean:                    float = 0.0
    Active_Std:                     float = 0.0
    Active_Max:                     float = 0.0
    Active_Min:                     float = 0.0
    Idle_Std:                       float = 0.0

    model_config = {
        "populate_by_name": True,
        "json_schema_extra": {
            "example": {
                "Flow_Duration": 109,
                "Total_Fwd_Packets": 1,
                "Total_Length_of_Fwd_Packets": 6,
                "Fwd_Packet_Length_Max": 6,
                "Fwd_Packet_Length_Min": 6,
                "Fwd_Packet_Length_Mean": 6.0,
                "Bwd_Packet_Length_Max": 6,
                "Bwd_Packet_Length_Min": 6,
                "Flow_Bytes/s": 110091.7,
                "Flow_Packets/s": 18348.62,
                "Flow_IAT_Mean": 109.0,
                "Flow_IAT_Std": 0.0,
                "Flow_IAT_Max": 109,
                "Flow_IAT_Min": 109,
                "Fwd_IAT_Mean": 0.0,
                "Fwd_IAT_Std": 0.0,
                "Fwd_IAT_Min": 0,
                "Bwd_IAT_Total": 0,
                "Bwd_IAT_Mean": 0.0,
                "Bwd_IAT_Std": 0.0,
                "Bwd_IAT_Max": 0,
                "Bwd_IAT_Min": 0,
                "Fwd_PSH_Flags": 0,
                "Fwd_Header_Length": 20,
                "Bwd_Header_Length": 20,
                "Bwd_Packets/s": 9174.31,
                "Min_Packet_Length": 6,
                "Max_Packet_Length": 6,
                "Packet_Length_Mean": 6.0,
                "Packet_Length_Variance": 0.0,
                "FIN_Flag_Count": 0,
                "RST_Flag_Count": 0,
                "PSH_Flag_Count": 0,
                "ACK_Flag_Count": 1,
                "URG_Flag_Count": 0,
                "Down/Up_Ratio": 1,
                "Fwd_Avg_Bytes/Bulk": 0,
                "Fwd_Avg_Packets/Bulk": 0,
                "Fwd_Avg_Bulk_Rate": 0,
                "Bwd_Avg_Bytes/Bulk": 0,
                "Bwd_Avg_Packets/Bulk": 0,
                "Bwd_Avg_Bulk_Rate": 0,
                "Init_Win_bytes_forward": 29,
                "Init_Win_bytes_backward": 256,
                "act_data_pkt_fwd": 0,
                "min_seg_size_forward": 20,
                "Active_Mean": 0.0,
                "Active_Std": 0.0,
                "Active_Max": 0,
                "Active_Min": 0,
                "Idle_Std": 0.0,
            }
        },
    }


# ══════════════════════════════════════════════════════════════════════
#  RESPONSE — single prediction
# ══════════════════════════════════════════════════════════════════════
class ThreatPrediction(BaseModel):
    rf_prediction:      str   = Field(..., description="Random Forest label")
    xgb_prediction:     str   = Field(..., description="XGBoost label")
    rf_confidence:      float = Field(..., description="RF confidence (0–1)")
    xgb_confidence:     float = Field(..., description="XGBoost confidence (0–1)")
    final_verdict:      str   = Field(..., description="Ensemble final label")
    severity:           str   = Field(..., description="none | medium | high | critical")
    recommended_action: str   = Field(..., description="Automated response suggestion")
    is_threat:          bool  = Field(..., description="True if a threat is detected")
    audit_record_id:    Optional[int] = Field(
        None, description="Merkle audit record id (only when LOGGING_MODE=merkle and a threat was logged)"
    )


# ══════════════════════════════════════════════════════════════════════
#  REQUEST — batch
# ══════════════════════════════════════════════════════════════════════
class BatchRequest(BaseModel):
    flows: List[NetworkFlow] = Field(..., description="List of network flows (max 1000)")

    model_config = {
        "json_schema_extra": {
            "example": {
                "flows": [
                    {"Flow_Duration": 109, "ACK_Flag_Count": 1},
                    {"Flow_Duration": 5000, "Flow_Bytes/s": 9999999, "FIN_Flag_Count": 1},
                ]
            }
        }
    }


# ══════════════════════════════════════════════════════════════════════
#  RESPONSE — batch
# ══════════════════════════════════════════════════════════════════════
class BatchPrediction(BaseModel):
    total_flows:    int
    threats_found:  int
    results:        List[ThreatPrediction]
    summary:        dict


# ══════════════════════════════════════════════════════════════════════
#  RESPONSE — health
# ══════════════════════════════════════════════════════════════════════
class HealthResponse(BaseModel):
    status:               str
    models_loaded:        bool
    blockchain_connected: bool  = False
    version:              str   = ""
    environment:          str   = ""
    message:              str
