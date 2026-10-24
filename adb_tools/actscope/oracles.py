"""Evidence-based, side-effect-free F1–F7 security oracles.

Input observations are measurements plus explicit experimenter attestations.  An
oracle validates consistency; it cannot independently authenticate a screenshot,
platform release confirmation, malware label, or a manually supplied assertion.
All times are Unix epoch milliseconds except fields explicitly ending in seconds.
"""
from __future__ import annotations

import math
import re
import shlex
from collections import defaultdict
from typing import Any

STATUSES = {"confirmed", "not_observed", "inconclusive", "not_applicable"}
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _hash(value: Any) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _same_hash(a: Any, b: Any) -> bool:
    return _hash(a) and _hash(b) and a.lower() == b.lower()


def _records(value: Any) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _result(mode: str, status: str, summary: str, evidence: Any = None,
            limitations: list[str] | None = None, **extra: Any) -> dict:
    return {"failure_mode": mode, "status": status, "summary": summary,
            "evidence": [] if evidence is None else evidence,
            "limitations": limitations or [], **extra}


def _f1(o: dict) -> dict:
    limits = ["仅覆盖本轮受控安装、实际可访问的路径及扫描时序；不证明跨租户安装劫持。"]
    required = (o.get("normal_baseline_verified") is True,
                _hash(o.get("original_sha256")), _hash(o.get("replacement_sha256")),
                _text(o.get("original_install_task_id")))
    if not all(required) or _same_hash(o.get("original_sha256"), o.get("replacement_sha256")):
        return _result("F1", "inconclusive", "缺少正常安装基线、不同的受控 APK 身份或原安装任务关联。", limitations=limits)
    bound = o.get("observed_install_task_id") == o["original_install_task_id"]
    identity = o.get("installed_identity_verified") is True
    distinct_markers = (_text(o.get("replacement_build_id")) and _text(o.get("requested_build_id"))
                        and o["replacement_build_id"] != o["requested_build_id"])
    alternate_identity = distinct_markers and o.get("installed_build_id") == o["replacement_build_id"]
    original_identity = (_same_hash(o.get("installed_sha256"), o["original_sha256"])
                         or (distinct_markers and o.get("installed_build_id") == o["requested_build_id"]))
    replacement = _same_hash(o.get("installed_sha256"), o["replacement_sha256"]) or alternate_identity
    for hash_key, marker_key, other_hash_key in (("original_sha256", "requested_build_id", "replacement_sha256"),
                                                ("replacement_sha256", "replacement_build_id", "original_sha256")):
        known_marker = _text(o.get(marker_key)) and _text(o.get("installed_build_id"))
        conflicts_with_hash = (_same_hash(o.get("installed_sha256"), o[hash_key])
                               and o.get("installed_build_id") != o.get(marker_key))
        conflicts_with_marker = (o.get("installed_build_id") == o.get(marker_key)
                                 and _same_hash(o.get("installed_sha256"), o[other_hash_key]))
        if known_marker and (conflicts_with_hash or conflicts_with_marker):
            return _result("F1", "inconclusive", "最终文件摘要与构建标记互相矛盾，须核对安装身份。", limitations=limits)
    proven = (o.get("replacement_attempted") is True and o.get("install_completed") is True
              and bound and identity and replacement and o.get("legitimate_transform_excluded") is True)
    evidence = {key: o.get(key) for key in ("original_install_task_id", "observed_install_task_id",
                "original_sha256", "replacement_sha256", "installed_sha256", "installed_build_id",
                "replacement_attempted", "install_completed")}
    if proven:
        return _result("F1", "confirmed", "原平台安装任务最终安装了受控替代 APK。", evidence, limits)
    if (o.get("observation_complete") is True and o.get("install_completed") is True and bound
            and identity and original_identity):
        return _result("F1", "not_observed", "本轮最终仍安装原始 APK，未观察到安装对象被劫持。", evidence, limits)
    return _result("F1", "inconclusive", "暂存文件暴露、替换成功或安装失败均不足以确认最终安装劫持。", evidence, limits)


def _f2(o: dict) -> dict:
    channels = _records(o.get("channels"))
    sample = o.get("sample_sha256")
    malware = o.get("maliciousness", {})
    if not isinstance(malware, dict):
        malware = {}
    valid = [c for c in channels if c.get("applicable") is True and c.get("completed") is True
             and _same_hash(c.get("sample_sha256"), sample) and _text(c.get("context_id"))
             and _text(c.get("name"))]

    def assessed(c: dict) -> bool:
        window = c.get("observation_window_seconds")
        return c.get("check_completed") is True or (_number(window) and window > 0)

    def admitted(c: dict) -> bool:
        return (c.get("outcome") in {"accepted", "warning_only"} and assessed(c)
                and c.get("prohibited_state_reached") is True and c.get("identity_verified") is True
                and _same_hash(c.get("installed_sha256"), sample))

    def blocked(c: dict) -> bool:
        return (c.get("outcome") in {"blocked", "removed_after_scan"}
                and c.get("security_reason") is True and c.get("prohibited_state_reached") is False)

    limits = ["仅评价给定样本和观察窗口；安装成功不能证明平台内部完全没有安全检查。"]
    official = [c for c in valid if c.get("official") is True]
    ground_truth = (_hash(sample) and malware.get("confirmed") is True
                    and malware.get("category") == "malware" and _text(malware.get("basis"))
                    and o.get("benign_baseline_ok") is True)
    if not ground_truth:
        eff = _result("F2-E", "inconclusive", "缺少已知恶意性依据或无害样本安装基线；资源占用不能自动认作恶意。")
    elif any(admitted(c) for c in official):
        accepted = [c for c in official if admitted(c)]
        eff = _result("F2-E", "confirmed", "已知恶意样本在官方入口的已记录观察范围内未被有效阻断。", accepted)
        if any(c.get("check_completed") is not True for c in accepted):
            eff["limitations"].append("扫描完成状态未知；结论仅限所记录的观察窗口，不能排除之后移除。")
    elif official and all(blocked(c) for c in official) and len(official) == len([c for c in channels if c.get("official") is True and c.get("applicable") is True]):
        eff = _result("F2-E", "not_observed", "官方入口对该样本实施了明确的安全阻断。", official)
    else:
        eff = _result("F2-E", "inconclusive", "没有足够的官方入口终态；普通安装错误不属于安全检出。", official)
    applicable_names = {c.get("name") for c in channels if c.get("applicable") is True and _text(c.get("name"))}
    pairs = [{"blocked_channel": a, "admitted_channel": b} for a in valid for b in valid
             if a["name"] != b["name"] and a["context_id"] == b["context_id"] and blocked(a) and admitted(b)]
    if len(applicable_names) < 2:
        con = _result("F2-C", "not_applicable", "没有第二条适用安装路径。")
    elif pairs and _hash(sample):
        con = _result("F2-C", "confirmed", "同一 APK 在相同测试条件下被一条路径安全阻断，却被另一条路径放行。", pairs)
    else:
        contexts = {c["context_id"] for c in valid}
        all_blocked = (len(contexts) == 1 and len({c["name"] for c in valid}) == len(applicable_names)
                       and len(valid) == len([c for c in channels if c.get("applicable") is True])
                       and valid and all(blocked(c) for c in valid))
        con = _result("F2-C", "not_observed" if all_blocked else "inconclusive",
                      "相同条件下已测路径均实施安全阻断。" if all_blocked else
                      "缺少同一 APK、相同测试条件下的有效阻断与另一渠道终态；全部放行不能额外证明策略绕过。", valid)
    status = ("confirmed" if "confirmed" in {eff["status"], con["status"]} else
              "not_observed" if eff["status"] == "not_observed" and con["status"] in {"not_observed", "not_applicable"}
              else "inconclusive")
    return _result("F2", status, "分别报告安装安全检查有效性 F2-E 与渠道一致性 F2-C。",
                   {"sample_sha256": sample}, limits, subresults={"effectiveness": eff, "consistency": con})


def _f3(o: dict) -> dict:
    cases = _records(o.get("cases"))
    results = []
    for case in cases:
        base = (case.get("baseline_healthy") is True and case.get("command_executed") is True
                and _text(case.get("command")))
        attributed = case.get("attribution_verified") is True
        kind = case.get("kind")
        unavailable = case.get("device_unavailable") is True or case.get("platform_control_unavailable") is True
        duration, minimum = case.get("observed_seconds"), case.get("min_observation_seconds")
        duration_ok = (_number(duration) and _number(minimum) and minimum > 0 and duration >= minimum)
        recovery = (case.get("normal_recovery_failed") is True and _text(case.get("recovery_evidence")))
        persistent_unavailability = unavailable and duration_ok and recovery
        persistent_network = (kind == "persistent_network" and case.get("configuration_changed") is True
                              and case.get("effect_verified") is True and case.get("cleanup_confirmed") is True
                              and case.get("persists_after_cleanup") is True)
        management = case.get("management_damage_verified") is True and _text(case.get("recovery_evidence"))
        if base and attributed and (persistent_unavailability or persistent_network or management):
            status, summary = "confirmed", "受控危险操作造成已归因的持续可用性、清理后配置或管理功能失效。"
        elif base and case.get("observation_complete") is True and (
                (kind == "reboot" and case.get("device_recovered") is True and case.get("normal_recovery_failed") is False
                 and case.get("device_unavailable") is False and case.get("platform_control_unavailable") is not True)
                or (kind == "persistent_network" and case.get("cleanup_confirmed") is True
                    and case.get("persists_after_cleanup") is False and case.get("device_unavailable") is False)
                or (kind == "management" and case.get("management_damage_verified") is False
                    and case.get("device_unavailable") is False)):
            status, summary = "not_observed", "该用例完成观察并正常恢复，未观察到规定的持续危害。"
        elif (case.get("baseline_healthy") is True and case.get("operation_blocked") is True
              and case.get("observation_complete") is True):
            status, summary = "not_observed", "危险操作被阻断，当前用例未观察到对应状态失效。"
        else:
            status, summary = "inconclusive", "命令接受或暂时断线不足以确认；需要实际持续影响、正常恢复结果和归因证据。"
        results.append(_result("F3", status, summary, case))
    status = ("confirmed" if any(r["status"] == "confirmed" for r in results) else
              "not_observed" if results and all(r["status"] == "not_observed" for r in results) else "inconclusive")
    return _result("F3", status, "按统一危险操作测试集的实际影响判定过度授权 ADB。", limitations=[
        "测试窗口内持续不可用不等于永久下线；全局代理写入成功不等于所有设备流量被接管。",
        "ADB 断开本身不能代替平台控制状态或正常恢复流程的证据。"], subresults={"cases": results})


def _f4(o: dict) -> dict:
    baseline, probe = o.get("baseline", {}), o.get("probe", {})
    if not isinstance(baseline, dict) or not isinstance(probe, dict):
        return _result("F4", "inconclusive", "缺少设备端基线和归还后操作观测。")
    end, issued, completed = o.get("session_end_server_ms"), probe.get("issued_at_server_ms"), probe.get("completed_at_server_ms")
    def is_device_operation(command: Any) -> bool:
        try:
            tokens = shlex.split(command) if isinstance(command, str) else []
        except ValueError:
            tokens = []
        if tokens and tokens[0].replace("\\", "/").rsplit("/", 1)[-1] in {"adb", "adb.exe"}:
            tokens = tokens[1:]
            while tokens and tokens[0].startswith("-"):
                if tokens[0] in {"-s", "-t", "-H", "-P", "-L"} and len(tokens) >= 2:
                    tokens = tokens[2:]
                elif tokens[0] in {"-d", "-e", "-a"}:
                    tokens = tokens[1:]
                else:
                    return False
        return bool(tokens) and tokens[0] in {"shell", "pull", "exec-out"}
    # Client-only state queries are never proof, regardless of exit code.
    device_operation = is_device_operation(probe.get("command"))
    common = (o.get("session_end_confirmed") is True and _number(end) and _number(issued)
              and _number(completed) and completed >= issued > end and baseline.get("success") is True
              and is_device_operation(baseline.get("command"))
              and _text(baseline.get("serial")) and baseline.get("serial") == probe.get("serial")
              and probe.get("old_authorization") is True and probe.get("reauthorized") is False)
    if common and device_operation and probe.get("success") is True and probe.get("device_response_verified") is True:
        return _result("F4", "confirmed", "会话确认结束后，旧授权完成了新发出的设备端操作。", probe,
                       ["未经后续会话关联，只证明归还后的访问，不能直接声称已访问下一租户。"])
    if common and probe.get("authorization_revoked") is True and probe.get("success") is False:
        return _result("F4", "not_observed", "本轮观测到旧授权明确被撤销。", probe,
                       ["结论仅限已验证的旧连接及授权；未覆盖其他调试入口。"])
    return _result("F4", "inconclusive", "在线列表、缓存状态、过滤/网络错误或新授权均不足以判断旧连接是否残留。", probe)


def _telemetry(o: dict) -> tuple[list[dict], list[str]]:
    """Return authenticated-by-context, distinct, conservatively fresh samples.

    The collector authenticates ingestion separately. Sorting uses sequence within
    a boot, not arrival order. Retries never gain freshness from reception time.
    """
    errors = []
    end = o.get("session_end_server_ms")
    if not (_number(end) and _text(o.get("expected_run_id")) and _text(o.get("expected_instance_id"))):
        return [], ["缺少归还时间及预期 run_id/instance_id。"]
    max_uncertainty = o.get("clock_max_uncertainty_ms", 2000)
    max_sync_age = o.get("clock_max_sync_age_ms", 300000)
    if not (_number(max_uncertainty) and max_uncertainty >= 0 and _number(max_sync_age) and max_sync_age >= 0):
        return [], ["时钟校验参数无效。"]
    groups: dict[int, list[dict]] = defaultdict(list)
    for raw in _records(o.get("events")):
        if raw.get("run_id") != o["expected_run_id"] or raw.get("instance_id") != o["expected_instance_id"]:
            errors.append("忽略不属于预期实验/实例的遥测。")
            continue
        if o.get("expected_build_id") and raw.get("build_id") != o["expected_build_id"]:
            errors.append("忽略构建身份不匹配的遥测。")
            continue
        numeric = ("sampled_at_device", "received_at_server", "clock_offset_ms", "clock_uncertainty_ms",
                   "clock_sync_age_ms", "elapsed_realtime_ms")
        seq = raw.get("sequence")
        if (not all(_number(raw.get(k)) for k in numeric) or not isinstance(seq, int) or isinstance(seq, bool)
                or seq < 0 or not _text(raw.get("boot_id")) or raw["elapsed_realtime_ms"] < 0):
            errors.append("忽略缺少有限时间值、启动分段或有效序号的遥测。")
            continue
        uncertainty = raw["clock_uncertainty_ms"]
        if not (0 <= uncertainty <= max_uncertainty and 0 <= raw["clock_sync_age_ms"] <= max_sync_age):
            errors.append("忽略时钟不确定性过大或同步过期的遥测。")
            continue
        corrected = raw["sampled_at_device"] + raw["clock_offset_ms"]
        if corrected - uncertainty > raw["received_at_server"]:
            errors.append("忽略校时后采样下界晚于服务器接收时间的异常遥测。")
            continue
        # Sequence is installation-wide (SQLite persists across reboot), matching
        # the collector's UNIQUE(run_id, instance_id, sequence) contract.
        groups[seq].append(dict(raw, sample_server_lower_ms=corrected - uncertainty,
                               sample_server_upper_ms=corrected + uncertainty))
    unique = []
    for duplicates in groups.values():
        content = [{k: v for k, v in d.items() if k not in {"received_at_server", "collector_event_id"}} for d in duplicates]
        if any(d != content[0] for d in content[1:]):
            errors.append("同一安装实例序号存在冲突采样（包括跨启动段重复），整组排除。")
            continue
        unique.append(min(duplicates, key=lambda d: d["received_at_server"]))
    by_boot: dict[str, list[dict]] = defaultdict(list)
    for event in unique:
        by_boot[event["boot_id"]].append(event)
    fresh = []
    for boot_events in by_boot.values():
        previous = None
        for event in sorted(boot_events, key=lambda d: d["sequence"]):
            if previous:
                elapsed_delta = event["elapsed_realtime_ms"] - previous["elapsed_realtime_ms"]
                wall_delta = event["sampled_at_device"] - previous["sampled_at_device"]
                corrected_delta = wall_delta + event["clock_offset_ms"] - previous["clock_offset_ms"]
                tolerance = event["clock_uncertainty_ms"] + previous["clock_uncertainty_ms"] + 2000
                if elapsed_delta <= 0 or abs(corrected_delta - elapsed_delta) > tolerance:
                    errors.append("启动段内墙钟/单调时钟不一致；异常后续样本排除，须重新同步或建立新段。")
                    continue
                if abs(wall_delta - elapsed_delta) > tolerance:
                    errors.append("检测到墙钟调整；使用每次校时偏差校正后的时间并对照单调时钟验证。")
            previous = event
            if event["sample_server_lower_ms"] > end:
                fresh.append(event)
    return sorted(fresh, key=lambda d: (d["sample_server_lower_ms"], d["sequence"])), list(dict.fromkeys(errors))


def _telemetry_scope(o: dict, fresh: list[dict]) -> dict:
    end = o["session_end_server_ms"]
    scope = {"fresh_event_count": len(fresh), "first_fresh_lower_ms": fresh[0]["sample_server_lower_ms"],
             "last_fresh_lower_ms": fresh[-1]["sample_server_lower_ms"],
             "minimum_survival_after_end_ms": fresh[-1]["sample_server_lower_ms"] - end,
             "boot_segments": sorted({e["boot_id"] for e in fresh})}
    for source, target in (("cleanup_ready_server_ms", "observed_after_cleanup"),
                           ("next_session_server_ms", "observed_after_next_session")):
        boundary = o.get(source)
        if _number(boundary) and boundary >= end:
            scope[target] = any(e["sample_server_lower_ms"] > boundary for e in fresh)
    return scope


def _f5_or_f7(mode: str, o: dict) -> dict:
    fresh, warnings = _telemetry(o)
    limits = ["遥测停止不能证明应用已卸载或权限已撤销。",
              "归还后存活与清理完成/下一租户边界分别报告；未提供边界证据时不声称跨租户影响。"]
    limits.extend(warnings)
    minimum = o.get("min_fresh_events", 2)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 2:
        return _result(mode, "inconclusive", "持续遥测至少需要两条不同的新采样。", limitations=limits)
    if o.get("baseline_telemetry_verified") is not True or len(fresh) < minimum:
        return _result(mode, "inconclusive", "缺少归还前遥测基线，或归还后可信新采样不足；旧消息及无消息均不能证明清理。",
                       {"fresh_event_count": len(fresh)}, limits)
    scope = _telemetry_scope(o, fresh)
    if mode == "F5":
        return _result(mode, "confirmed", "同一实验安装实例在归还后持续产生新的遥测。", scope, limits)
    component = o.get("a11y_component")
    if not (_text(component) and o.get("initial_a11y_enabled") is True and o.get("reauthorized") is False):
        return _result(mode, "inconclusive", "缺少特定服务初始授权及归还后未重新授权的记录。", scope, limits)
    permission_samples = []
    max_age = o.get("a11y_max_sample_age_ms", 5000)
    if not _number(max_age) or max_age < 0:
        return _result(mode, "inconclusive", "权限采样时间校验参数无效。", scope, limits)
    for event in fresh:
        stamp = event.get("a11y_sampled_at")
        if (event.get("a11y_component") == component and type(event.get("a11y_enabled")) is bool
                and _number(stamp) and abs(stamp - event["sampled_at_device"]) <= max_age
                and stamp + event["clock_offset_ms"] - event["clock_uncertainty_ms"] > o["session_end_server_ms"]
                and stamp + event["clock_offset_ms"] - event["clock_uncertainty_ms"] <= event["received_at_server"]):
            permission_samples.append(event)
    scope["permission_sample_count"] = len(permission_samples)
    scope["a11y_component"] = component
    limits.append("F7 确认的是特定 Accessibility 服务授权启用状态，不自动证明服务存活或屏幕读取/输入控制。")
    enabled = [e for e in permission_samples if e["a11y_enabled"] is True]
    if enabled:
        scope["enabled_sample_count"] = len(enabled)
        scope["last_enabled_lower_ms"] = max(e["a11y_sampled_at"] + e["clock_offset_ms"] - e["clock_uncertainty_ms"] for e in enabled)
        return _result(mode, "confirmed", "归还后新查询显示原先授予的特定 Accessibility 服务仍启用。", scope, limits)
    if permission_samples and len(permission_samples) == len(fresh):
        return _result(mode, "not_observed", "归还后的有效采样点中，该服务均为 disabled。", scope, limits)
    return _result(mode, "inconclusive", "应用仍运行，但权限状态为 unknown、过期、其他组件或缺少本次查询。", scope, limits)


def _f6(o: dict) -> dict:
    files = _records(o.get("files"))
    ui = _records(o.get("ui"))
    positives, candidates = [], []
    for file in files:
        if file.get("exists") is False or file.get("kind") in {"missing", "directory"} or file.get("public_resource") is True:
            continue
        provenance = _text(file.get("provenance_evidence")) or _text(file.get("evidence_ref"))
        if (file.get("kind") == "file" and file.get("exists") is True
                and file.get("expected_cleanup") is True and file.get("attributed_to_prior_session") is True
                and file.get("public_resource") is False and _text(file.get("path")) and provenance):
            positives.append(file)
        else:
            candidates.append(file)
    if positives:
        file_result = _result("F6-file", "confirmed", "先前会话应清理的实际文件仍存在；不要求 UI 再确认。", positives)
    elif o.get("file_scan_complete") is True and not candidates and not o.get("access_errors"):
        file_result = _result("F6-file", "not_observed", "已完成的可访问路径扫描中未观察到可归属的残留文件。")
    else:
        file_result = _result("F6-file", "inconclusive", "文件候选缺少会话来源/清理依据，或扫描因访问受限尚不完整。", candidates)
    visible = [u for u in ui if u.get("prior_session_content_visible") is True
               and u.get("attributed_to_prior_session") is True and _text(u.get("evidence_ref"))]
    ambiguous = [u for u in ui if u.get("prior_session_content_visible") is not False and u not in visible]
    if visible:
        ui_result = _result("F6-ui", "confirmed", "UI 证据显示先前会话的应用状态或内容。", visible)
    elif o.get("ui_scan_complete") is True and not ambiguous:
        ui_result = _result("F6-ui", "not_observed", "已检查的 UI 流程中未观察到原会话内容。", ui)
    else:
        ui_result = _result("F6-ui", "inconclusive", "UI 未完成或缺少原会话内容的关联证据。", ui)
    statuses = {file_result["status"], ui_result["status"]}
    status = "confirmed" if "confirmed" in statuses else "not_observed" if statuses == {"not_observed"} else "inconclusive"
    # Execution coverage explains skipped/failed flows without treating app
    # presence, a successful click, or batch completion as residue evidence.
    coverage = {"file_scan_complete": o.get("file_scan_complete"),
                "ui_scan_complete": o.get("ui_scan_complete")}
    for key in ("batch_execution_complete", "ui_execution_status"):
        if key in o:
            coverage[key] = o[key]
    supplied_counts = o.get("ui_execution_coverage")
    if isinstance(supplied_counts, dict):
        coverage["ui_execution_coverage"] = {key: supplied_counts[key]
            for key in ("flow_completed", "skipped", "failed_or_manual", "remaining")
            if type(supplied_counts.get(key)) is int and supplied_counts[key] >= 0}
    package_checks = _records(o.get("package_checks"))
    if package_checks:
        coverage["package_checks"] = [{key: row.get(key) for key in ("target", "package", "installed", "status")}
                                       for row in package_checks[:512]]
        if len(package_checks) > 512:
            coverage["package_checks_truncated"] = True
    return _result("F6", status, "先文件扫描、再 UI 观测；任一阶段阳性即确认数据残留。", evidence=coverage, limitations=[
        "文件残留不自动等于已验证的敏感数据泄漏；扫描结果限于实际身份可访问的路径。",
        "规则命中、空目录和公共资源不能单独证明原会话残留。",
        "应用安装状态和 UI 流程执行覆盖仅作测量范围说明，不参与残留判定。"],
        subresults={"file_residue": file_result, "ui_residue": ui_result})


def evaluate(failure_mode: str, observation: dict) -> dict:
    """Evaluate one observation without executing commands or touching devices."""
    mode = str(failure_mode).upper()
    if mode not in {f"F{i}" for i in range(1, 8)}:
        raise ValueError(f"Unknown failure mode: {failure_mode!r}")
    if not isinstance(observation, dict):
        raise TypeError("observation must be a dict")
    if observation.get("supported") is False:
        return _result(mode, "not_applicable", observation.get("unsupported_reason") or "所需执行/观测能力不可用。")
    if mode in {"F5", "F7"}:
        result = _f5_or_f7(mode, observation)
    else:
        result = {"F1": _f1, "F2": _f2, "F3": _f3, "F4": _f4, "F6": _f6}[mode](observation)
    example = observation.get("_example")
    if isinstance(example, dict) and example.get("synthetic") is True:
        result["synthetic_fixture"] = True
        result["summary"] = "[合成样例，非平台实测] " + result["summary"]
        result["limitations"].insert(0, "输入是离线合成样例；此判定不得计入真实平台实验统计。")
    return result
