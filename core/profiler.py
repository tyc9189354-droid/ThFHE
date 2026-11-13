import time
import math
import tracemalloc
from typing import Callable, Any, Tuple, List, Dict
from core.metrics import StageMetric

class Profiler:
    """高精準度效能與記憶體 Profiler"""

    @staticmethod
    def measure_execution(
        func: Callable[[], Any],
        iterations: int = 5,
        warmup: int = 1,
        stage_name: str = "stage"
    ) -> Tuple[Any, StageMetric]:
        """
        量測某個函數的執行時間 (ms) 與記憶體增量 (KB)。
        :param func: 要量測的目標無參 Callable
        :param iterations: 正式量測重複次數
        :param warmup: 預熱次數（避免 JIT、快取初次載入偏差）
        :param stage_name: 階段名稱
        :return: (最後一次執行的傳回值, StageMetric 統計對象)
        """
        # Warm-up phase
        for _ in range(warmup):
            func()

        times_ms: List[float] = []
        last_result = None

        # Memory tracking
        tracemalloc.start()
        start_mem_peak = 0

        for _ in range(iterations):
            t_start = time.perf_counter_ns()
            last_result = func()
            t_end = time.perf_counter_ns()
            times_ms.append((t_end - t_start) / 1_000_000.0)

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        mean_time = sum(times_ms) / len(times_ms)
        variance = sum((x - mean_time) ** 2 for x in times_ms) / len(times_ms) if len(times_ms) > 1 else 0.0
        std_time = math.sqrt(variance)

        min_t = min(times_ms) if times_ms else 0.0
        max_t = max(times_ms) if times_ms else 0.0

        metric = StageMetric(
            stage_name=stage_name,
            iterations=iterations,
            mean_time_ms=round(mean_time, 4),
            std_time_ms=round(std_time, 4),
            min_time_ms=round(min_t, 4),
            max_time_ms=round(max_t, 4),
            memory_peak_kb=round(peak / 1024.0, 2),
            details={"raw_times_ms": times_ms}
        )

        return last_result, metric
