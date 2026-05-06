"""Safe dataframe analysis helpers for run_analysis()."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from sift_mcp.models.sigma import AnalysisResult

BLOCKED_PATTERNS: tuple[str, ...] = (
    "import ",
    "exec(",
    "eval(",
    "__",
    "open(",
    "os.",
    "sys.",
    "subprocess",
    "shutil",
    "pathlib",
    "glob",
    "pd.read_csv",
    "pd.read_json",
    "pd.read_sql",
    "pd.read_excel",
    "pd.read_html",
    "pd.read_xml",
    "pd.read_parquet",
    "pd.read_feather",
    "pd.read_hdf",
    "pd.read_pickle",
    "pd.read_clipboard",
    "pd.read_fwf",
    "pd.read_orc",
    "pd.read_spss",
    "pd.read_table",
    "pd.io",
    "excelwriter",
    "hdfstore",
    ".to_csv(",
    ".to_json(",
    ".to_excel(",
    ".to_sql(",
    ".to_pickle(",
    ".to_hdf(",
    ".to_parquet(",
    ".to_feather(",
    ".to_html(",
    "getattr(",
    "setattr(",
    "delattr(",
    "vars(",
    "dir(",
)


class SafeAnalysisError(RuntimeError):
    """Raised when a run_analysis query is unsafe or cannot be evaluated safely."""


def _normalized_query(query: str) -> str:
    return re.sub(r"\s+", "", query.lower())


def blocked_pattern(query: str) -> str | None:
    lowered = query.lower()
    collapsed = _normalized_query(query)
    for pattern in BLOCKED_PATTERNS:
        token = pattern.lower()
        if token in lowered or token.replace(" ", "") in collapsed:
            return pattern
    return None


def _load_dataframe(path: Path):
    import pandas as pd

    if path.suffix.lower() == ".json":
        df = pd.read_json(path)
    else:
        df = pd.read_csv(path, low_memory=False)
    return df, pd


def _build_interpreter(usersyms: dict[str, Any]):
    if sys.modules.get("asteval") is None and "asteval" in sys.modules:
        raise SafeAnalysisError(
            "run_analysis requires the 'asteval' package to be installed for safe evaluation."
        )
    try:
        from asteval import Interpreter
    except ImportError:
        return None

    try:
        return Interpreter(usersyms=usersyms, minimal=True, builtins_readonly=True)
    except TypeError:
        return Interpreter(usersyms=usersyms)


def _evaluate_query(query: str, df, np_module):
    usersyms = {
        "df": df,
        "np": np_module,
        "len": len,
        "min": min,
        "max": max,
        "sum": sum,
        "abs": abs,
        "sorted": sorted,
    }
    interpreter = _build_interpreter(usersyms)
    if interpreter is None:
        # Fallback for minimal environments that do not ship the optional
        # asteval dependency. The query has already passed the blocklist above;
        # keep builtins empty and expose only the explicit dataframe symbols.
        try:
            return eval(compile(query, "<run_analysis>", "eval"), {"__builtins__": {}}, usersyms)
        except Exception as exc:
            raise SafeAnalysisError(f"Query evaluation error: {exc}") from exc

    result = interpreter(query)

    errors = getattr(interpreter, "error", [])
    if errors:
        messages: list[str] = []
        for error in errors:
            if hasattr(error, "msg") and error.msg:
                messages.append(str(error.msg))
            else:
                messages.append(str(error))
        raise SafeAnalysisError("Query evaluation error: " + "; ".join(messages))

    return result


def run_safe_analysis(
    data_path: str,
    query: str,
    output_format: str = "table",
) -> dict[str, Any]:
    """Load a dataframe, evaluate a safe query, and return AnalysisResult payload."""
    path = Path(data_path).resolve()
    if not path.exists():
        raise SafeAnalysisError(f"File not found: {data_path}")

    pattern = blocked_pattern(query)
    if pattern:
        raise SafeAnalysisError(f"Query contains blocked pattern: {pattern}")

    import numpy as np

    df, pd = _load_dataframe(path)
    result_obj = _evaluate_query(query, df, np)

    if isinstance(result_obj, pd.DataFrame):
        result_df = result_obj
    elif isinstance(result_obj, pd.Series):
        result_df = result_obj.to_frame()
    else:
        result_df = pd.DataFrame({"result": [result_obj]})

    if len(result_df) > 500:
        result_df = result_df.head(500)

    if output_format == "json":
        table_str = result_df.to_json(orient="records", indent=2)
    elif output_format == "csv":
        table_str = result_df.to_csv(index=False)
    else:
        try:
            from tabulate import tabulate

            table_str = tabulate(
                result_df, headers="keys", tablefmt="pipe", showindex=False
            )
        except ImportError:
            table_str = result_df.to_string()

    insights: list[str] = []
    if len(result_df) > 0:
        insights.append(f"Query returned {len(result_df)} rows")
        for col in result_df.columns:
            if result_df[col].dtype in ("int64", "float64"):
                insights.append(
                    f"{col}: min={result_df[col].min()}, max={result_df[col].max()}, mean={result_df[col].mean():.2f}"
                )

    analysis = AnalysisResult(
        query=query,
        result_table=table_str,
        row_count=len(result_df),
        columns=list(result_df.columns),
        insights=insights,
        data_source=str(path),
    )
    return analysis.model_dump()
