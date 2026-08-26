from __future__ import annotations

from typing import Any, Mapping

import pandas as pd

class FeatureToTextConverter:
    """Convert structured IDS features into text for transformer training."""

    PROTOCOLS = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
    }

    def _get(self, row: Mapping[str, Any], key: str, default: Any = "unknown") -> Any:
        value = row.get(key, default)
        if pd.isna(value):
            return default
        return value

    def _protocol_name(self, protocol: Any) -> str:
        try:
            protocol_num = int(protocol)
        except (TypeError, ValueError):
            protocol_text = str(protocol).strip()
            return protocol_text.upper() if protocol_text else "unknown protocol"

        return self.PROTOCOLS.get(protocol_num, f"protocol {protocol_num}")

    def network_flow_to_text(self, row: Mapping[str, Any]) -> str:
        src_ip = self._get(row, "src_ip")
        dst_ip = self._get(row, "dst_ip")
        src_port = self._get(row, "src_port", 0)
        dst_port = self._get(row, "dst_port", 0)
        protocol = self._protocol_name(self._get(row, "protocol", 6))

        duration = self._get(row, "duration_s", 0)
        fwd_pkts = self._get(row, "tot_fwd_pkts", 0)
        bwd_pkts = self._get(row, "tot_bwd_pkts", 0)
        total_bytes = self._get(row, "tot_bytes", 0)
        flow_pkts_per_s = self._get(row, "flow_pkts_per_s", 0)
        flow_iat_mean = self._get(row, "flow_iat_mean_s", 0)
        fwd_pkt_len_mean = self._get(row, "fwd_pkt_len_mean", 0)
        bwd_pkt_len_mean = self._get(row, "bwd_pkt_len_mean", 0)

        context = []
        if self._as_bool(self._get(row, "src_is_pod", False)):
            context.append("source is a Kubernetes pod")
        if self._as_bool(self._get(row, "dst_is_pod", False)):
            context.append("destination is a Kubernetes pod")
        if self._as_bool(self._get(row, "dst_is_service", False)):
            context.append("destination is a Kubernetes service")

        context_text = (
            f" Kubernetes context: {', '.join(context)}."
            if context
            else " No Kubernetes pod or service context was detected."
        )

        return (
            f"Network flow from source IP {src_ip} port {src_port} "
            f"to destination IP {dst_ip} port {dst_port} using {protocol}. "
            f"The flow lasted {duration} seconds and contained {fwd_pkts} forward packets "
            f"and {bwd_pkts} backward packets with {total_bytes} total bytes. "
            f"Average forward packet length was {fwd_pkt_len_mean}, and average backward "
            f"packet length was {bwd_pkt_len_mean}. "
            f"The packet rate was {flow_pkts_per_s} packets per second, and the mean "
            f"inter-arrival time was {flow_iat_mean} seconds."
            f"{context_text}"
        )

    def api_audit_to_text(self, row: Mapping[str, Any]) -> str:
        user = self._get(row, "user")
        verb = self._get(row, "verb")
        resource = self._get(row, "resource")
        namespace = self._get(row, "namespace")
        source_ip = self._get(row, "source_ip")
        response_code = self._get(row, "response_code")

        return (
            f"Kubernetes API audit event where user {user} performed action {verb} "
            f"on resource {resource} in namespace {namespace} from source IP {source_ip}. "
            f"The API server returned response code {response_code}."
        )

    def _as_bool(self, value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y"}
        return bool(value)

def create_text_dataset(
    df: pd.DataFrame,
    feature_type: str = "network",
    label_col: str = "label",
) -> pd.DataFrame:
    converter = FeatureToTextConverter()

    if feature_type == "network":
        texts = [converter.network_flow_to_text(row.to_dict()) for _, row in df.iterrows()]
    elif feature_type in {"api", "audit", "api_audit"}:
        texts = [converter.api_audit_to_text(row.to_dict()) for _, row in df.iterrows()]
    else:
        raise ValueError(f"Unsupported feature_type: {feature_type}")

    output = pd.DataFrame({"text": texts})
    if label_col in df.columns:
        output["label"] = df[label_col].values

    return output
