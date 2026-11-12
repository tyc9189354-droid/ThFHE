import json
import base64
import pickle
import urllib.request
import urllib.error
from typing import Any, List, Optional, Dict
from network.comm_tracker import CommStats

class BenchmarkClient:
    """
    與雲端 Server 互動的通訊客戶端，內建自動通訊量與輪數統計。
    支援純 Python 標準庫 urllib，無需強制依賴第三方套件。
    """

    def __init__(self, server_url: str = "http://127.0.0.1:8000"):
        self.server_url = server_url.rstrip("/")
        self.comm_stats = CommStats()

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}{endpoint}"
        body_bytes = json.dumps(payload).encode("utf-8")
        self.comm_stats.record_send(len(body_bytes))

        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_bytes = resp.read()
                self.comm_stats.record_receive(len(resp_bytes))
                return json.loads(resp_bytes.decode("utf-8"))
        except urllib.error.URLError as e:
            raise ConnectionError(f"Failed to communicate with server at {url}: {e}")

    def check_health(self) -> bool:
        url = f"{self.server_url}/health"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                self.comm_stats.record_receive(len(resp.read()))
                return resp.status == 200
        except Exception:
            return False

    def setup_remote(self, scheme_name: str, security_param: int, threshold_t: int, total_n: int):
        payload = {
            "scheme": scheme_name,
            "security_param": security_param,
            "threshold_t": threshold_t,
            "total_n": total_n
        }
        return self._post("/api/setup", payload)

    def eval_remote(self, scheme_name: str, op: str, ct1: Any, ct2: Any, eval_key: Optional[Any] = None) -> Any:
        ct1_b64 = base64.b64encode(pickle.dumps(ct1)).decode("ascii")
        ct2_b64 = base64.b64encode(pickle.dumps(ct2)).decode("ascii")
        payload = {
            "scheme": scheme_name,
            "op": op,
            "ct1": ct1_b64,
            "ct2": ct2_b64
        }
        if eval_key is not None:
            payload["eval_key"] = base64.b64encode(pickle.dumps(eval_key)).decode("ascii")

        resp = self._post("/api/eval", payload)
        res_bytes = base64.b64decode(resp["result_ct"])
        return pickle.loads(res_bytes)

    def combine_remote(self, scheme_name: str, shares: List[Any], ct: Any, pk: Optional[Any] = None) -> Any:
        shares_b64 = [base64.b64encode(pickle.dumps(s)).decode("ascii") for s in shares]
        ct_b64 = base64.b64encode(pickle.dumps(ct)).decode("ascii")
        payload = {
            "scheme": scheme_name,
            "shares": shares_b64,
            "ciphertext": ct_b64
        }
        if pk is not None:
            payload["pk"] = base64.b64encode(pickle.dumps(pk)).decode("ascii")

        resp = self._post("/api/combine", payload)
        return resp.get("plaintext")
