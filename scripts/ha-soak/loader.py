#!/usr/bin/env python3
"""wp28 HA soak — in-network load + chaos driver.

Runs INSIDE a container on the compose network (so it can address the scaled `chancela-cluster`
replicas directly by container name — they publish no host port) with the docker socket mounted (so
it can inject faults against sibling containers). Standard library only.

What it does, for --duration seconds:
  (i)  sustained WRITE load across all nodes — each writer thread targets the current leader and
       creates real ledger-writing entities (POST /v1/entities), following 307s a follower issues.
  (ii) scheduled FAULTS: kill the current leader (force failover) + revive it; restart Postgres;
       pause/unpause (partition) a follower.
  (iii) records throughput, errors, 5xx, redirects, per-fault failover (write-resume) time, and the
       leader timeline (asserting never >1 leader at once).

Then a QUIESCE/SETTLE phase (so we never grade the cluster mid-election right after the last fault):
faults stop a margin before load ends; once load stops we recover any lingering fault (un-pause a
partitioned follower, restart a killed node / Postgres) and poll up to a bounded settle-timeout for
the cluster to re-elect and fully converge. THEN a CORRECTNESS check: polls every node's /health
(cluster.applied_seq / durable_max_seq) and /v1/ledger/verify, asserts all surviving nodes converge
to the same durable head with an intact hash-chain, exactly one leader, and that no committed ledger
events were lost or duplicated. If the settle-timeout elapses without single-leader + convergence,
that is a real FAIL (reported honestly, not papered over).

Exit code 0 iff the soak ran and all correctness assertions held; non-zero otherwise.
"""

import argparse
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# ----------------------------------------------------------------------------------------------
# HTTP with manual 307 handling (urllib will not replay a POST body across a cross-host 307).
# ----------------------------------------------------------------------------------------------


def http(method, url, headers=None, body=None, timeout=8, _redirects=0):
    headers = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, dict(resp.headers), raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        # Follow a 307/308 to the leader, preserving method + body (single hop guard).
        if e.code in (307, 308) and _redirects < 3:
            loc = e.headers.get("Location")
            if loc:
                return http(method, loc, headers, body, timeout, _redirects + 1)
        return e.code, dict(e.headers), raw
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return None, {}, repr(e).encode()


def get_json(url, headers=None, timeout=8):
    st, _, raw = http("GET", url, headers=headers, timeout=timeout)
    if st == 200:
        try:
            return json.loads(raw)
        except Exception:
            return None
    return None


# ----------------------------------------------------------------------------------------------
# docker control (socket mounted; docker-cli installed at container start)
# ----------------------------------------------------------------------------------------------


def docker(*args, check=False):
    r = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=60
    )
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {r.stderr.strip()}")
    return r.returncode, r.stdout.strip(), r.stderr.strip()


class Soak:
    def __init__(self, a):
        self.nodes = a.nodes.split(",")  # http hostnames == container names here
        self.port = a.port
        self.pg = a.postgres_container
        self.duration = a.duration
        # Quiesce/settle knobs: stop injecting new faults this many seconds before the load phase
        # ends, and — after load stops and the cluster is recovered — poll up to settle_timeout for
        # the cluster to re-elect + fully converge BEFORE the final correctness snapshot.
        self.fault_stop_margin = max(0, a.fault_stop_margin)
        self.settle_timeout = max(0, a.settle_timeout)
        self.settle_poll = 2  # seconds between settle sweeps
        self.metrics_out = a.metrics_out
        self.session = None  # x-chancela-session token (Redis-shared → valid on any node)
        self.user_id = None
        self.stop = threading.Event()
        self.lock = threading.Lock()
        # metrics
        self.writes_ok = 0
        self.writes_fail = 0
        self.status_counts = {}
        self.redirects = 0
        self.last_write_ok_ts = None
        self.leader_timeline = []  # (ts, leader_node_or_None, num_leaders)
        self.multi_leader_violations = 0
        self.no_leader_windows = 0
        self.faults = []  # dicts
        self.errors_sample = []

    def url(self, node, path):
        return f"http://{node}:{self.port}{path}"

    # ---- leadership ----
    def node_health(self, node):
        return get_json(self.url(node, "/health"), timeout=5)

    def current_leader(self):
        """Return (leader_node|None, num_leaders_seen) from a single /health sweep."""
        leaders = []
        for n in self.nodes:
            h = self.node_health(n)
            if h and isinstance(h.get("cluster"), dict) and h["cluster"].get("role") == "leader":
                leaders.append(n)
        return (leaders[0] if leaders else None), len(leaders)

    def wait_for_leader(self, timeout=90):
        deadline = time.time() + timeout
        while time.time() < deadline and not self.stop.is_set():
            ldr, n = self.current_leader()
            if ldr and n == 1:
                return ldr
            time.sleep(1)
        return None

    # ---- bootstrap: first user (no session) + login ----
    def bootstrap(self):
        ldr = self.wait_for_leader()
        if not ldr:
            raise RuntimeError("no single leader elected during bootstrap window")
        # First user needs no session and is auto-Owner@Global.
        st, _, raw = http(
            "POST",
            self.url(ldr, "/v1/users"),
            body={
                "username": "amelia.marques",
                "display_name": "Amelia Marques",
                "email": "amelia.marques@example.test",
                "password": "Soak-Ladder-C-Passw0rd-2026!",
            },
            timeout=15,
        )
        if st not in (200, 201):
            raise RuntimeError(f"bootstrap user create failed: {st} {raw[:300]!r}")
        self.user_id = json.loads(raw).get("id")
        # Login → session token (shared via Redis across nodes).
        st, _, raw = http(
            "POST",
            self.url(ldr, "/v1/session"),
            body={"user_id": self.user_id, "password": "Soak-Ladder-C-Passw0rd-2026!"},
            timeout=15,
        )
        if st not in (200, 201):
            raise RuntimeError(f"login failed: {st} {raw[:300]!r}")
        self.session = json.loads(raw)["token"]
        print(f"[bootstrap] user={self.user_id} session=ok leader={ldr}", flush=True)

    # ---- write load ----
    def writer_thread(self, wid):
        hdr = {"x-chancela-session": self.session}
        i = 0
        leader = self.wait_for_leader(timeout=30)
        while not self.stop.is_set():
            i += 1
            if leader is None:
                leader = self.wait_for_leader(timeout=15)
                if leader is None:
                    with self.lock:
                        self.writes_fail += 1
                    continue
            body = {
                "name": f"Encosto Estrategico W{wid}-{i} Lda",
                "nipc": f"5{wid:02d}{i:06d}"[:9],
                "seat": "Lisboa",
                "kind": "SociedadePorQuotas",
                "allow_invalid_nipc": True,
            }
            st, h, raw = http("POST", self.url(leader, "/v1/entities"), hdr, body, timeout=8)
            with self.lock:
                self.status_counts[st] = self.status_counts.get(st, 0) + 1
                if st in (200, 201):
                    self.writes_ok += 1
                    self.last_write_ok_ts = time.time()
                else:
                    self.writes_fail += 1
                    if st is None or (isinstance(st, int) and st >= 500) or st == 503:
                        # leader likely gone / stepped down → re-resolve
                        if len(self.errors_sample) < 40:
                            self.errors_sample.append(
                                {"t": round(time.time(), 2), "st": st, "b": raw[:120].decode("utf-8", "replace")}
                            )
                        leader = None
            # tiny pacing so a single node isn't the only bottleneck
            time.sleep(0.01)

    # ---- leadership monitor ----
    def leader_monitor(self):
        while not self.stop.is_set():
            ldr, n = self.current_leader()
            ts = time.time()
            with self.lock:
                self.leader_timeline.append((round(ts, 2), ldr, n))
                if n > 1:
                    self.multi_leader_violations += 1
                if n == 0:
                    self.no_leader_windows += 1
            time.sleep(1)

    # ---- helpers ----
    def _sleep(self, secs):
        """Sleep up to `secs`, but wake immediately once stop is set (so chaos exits promptly
        at end-of-load and can run its recovery cleanup instead of blocking a full fault window)."""
        end = time.time() + secs
        while not self.stop.is_set():
            rem = end - time.time()
            if rem <= 0:
                break
            time.sleep(min(1.0, rem))

    def _container_running(self, name):
        rc, out, _ = docker("inspect", "-f", "{{.State.Running}}", name)
        return out == "true"

    def _recover_cluster(self, grace=5):
        """Undo any lingering fault before settling: un-pause / un-partition every app node, make
        sure any killed/restarted app node + Postgres is back up. Idempotent (unpause/start on an
        already-healthy container is a harmless no-op)."""
        print("[settle] recovering cluster: unpause + ensure all nodes and postgres are up", flush=True)
        if not self._container_running(self.pg):
            docker("start", self.pg)
        for n in self.nodes:
            docker("unpause", n)  # no-op if not paused
            if not self._container_running(n):
                docker("start", n)
        # brief grace for containers / postgres to accept connections again before we poll
        time.sleep(grace)

    def _strict_converged(self, snap):
        """STRICT quiescence predicate over one cluster sweep. Returns (converged, target_seq).

        converged == True requires ALL of:
          * exactly one node reports role==leader,
          * every node reports a durable_max_seq and applied_seq,
          * every node's durable_max_seq == the max durable head across nodes (target),
          * every node's applied_seq == target (fully applied, lag 0),
          * every node reports lag 0 (where lag is present),
          * every node's hash-chain verifies valid,
          * every node reports the same ledger head seq AND head hash.
        This is the same bar the final verdict enforces — so the sweep we break on IS a passing one.
        """
        if not snap or len(snap) != len(self.nodes):
            return False, None
        durs, applied, lags, valids, seqs, hashes = [], [], [], [], [], []
        leaders = 0
        for n in self.nodes:
            s = snap.get(n)
            if not s:
                return False, None
            h = s.get("health")
            if not h or not isinstance(h.get("cluster"), dict):
                return False, None
            c = h["cluster"]
            if c.get("role") == "leader":
                leaders += 1
            durs.append(c.get("durable_max_seq"))
            applied.append(c.get("applied_seq"))
            lags.append(c.get("lag"))
            v = s.get("verify")
            valids.append(bool(v and v.get("valid")))
            seqs.append(s.get("head_seq"))
            hashes.append(s.get("head_hash"))
        if leaders != 1:
            return False, None
        if any(d is None for d in durs) or any(a is None for a in applied):
            return False, None
        target = max(durs)
        if not all(d == target for d in durs):
            return False, target
        if not all(a == target for a in applied):
            return False, target
        if any(lag not in (0, None) for lag in lags):
            return False, target
        if not all(valids):
            return False, target
        if any(x is None for x in seqs) or len(set(seqs)) != 1:
            return False, target
        if any(x is None for x in hashes) or len(set(hashes)) != 1:
            return False, target
        return True, target

    # ---- chaos ----
    def measure_failover_after(self, label, t_fault):
        """Wait until a write succeeds after t_fault; return resume seconds."""
        deadline = time.time() + 120
        while time.time() < deadline and not self.stop.is_set():
            with self.lock:
                lw = self.last_write_ok_ts
            if lw and lw >= t_fault:
                return round(lw - t_fault, 2)
            time.sleep(0.2)
        return None

    def record_fault(self, kind, target, t, extra=None):
        e = {"kind": kind, "target": target, "t": round(t, 2)}
        if extra:
            e.update(extra)
        with self.lock:
            self.faults.append(e)
        print(f"[fault] {kind} {target} @ {e['t']}", flush=True)
        return e

    def chaos_thread(self):
        # Fault schedule: begin after a warmup, cycle through fault types, and STOP injecting new
        # faults `fault_stop_margin` seconds before the load phase ends — so the cluster has clean
        # air (no fresh kill/restart/partition) leading into the post-load settle + snapshot.
        warmup = 60
        cycle = max(90, (self.duration - warmup) // 6)  # ~6 fault cycles
        t0 = time.time()
        fault_deadline = self.duration - self.fault_stop_margin
        try:
            self._sleep(min(warmup, max(5, self.duration // 20)))
            cyc = 0
            while not self.stop.is_set() and (time.time() - t0) < fault_deadline:
                cyc += 1
                phase = (cyc - 1) % 3
                if phase == 0:
                    # KILL current leader → forced failover, then revive it.
                    ldr, _ = self.current_leader()
                    if ldr:
                        t = time.time()
                        docker("kill", ldr)
                        e = self.record_fault("kill-leader", ldr, t)
                        resume = self.measure_failover_after("kill-leader", t)
                        e["failover_resume_s"] = resume
                        print(f"[fault] kill-leader {ldr} resume={resume}s", flush=True)
                        self._sleep(15)
                        docker("start", ldr)  # bring the node back as a follower
                elif phase == 1:
                    # RESTART Postgres → leader must step down (watchdog) & re-elect after PG returns.
                    t = time.time()
                    docker("restart", "-t", "5", self.pg)
                    e = self.record_fault("restart-postgres", self.pg, t)
                    resume = self.measure_failover_after("restart-postgres", t)
                    e["failover_resume_s"] = resume
                    print(f"[fault] restart-postgres resume={resume}s", flush=True)
                else:
                    # PAUSE (partition) a follower for a window, then unpause.
                    ldr, _ = self.current_leader()
                    follower = next((n for n in self.nodes if n != ldr), None)
                    if follower:
                        t = time.time()
                        rc, _, _ = docker("pause", follower)
                        if rc == 0:
                            self.record_fault("pause-follower", follower, t, {"hold_s": 20})
                            self._sleep(20)
                            docker("unpause", follower)
                # wait out the rest of the cycle (unless we've reached the fault deadline / stopped)
                waited = 0
                while (
                    waited < cycle
                    and not self.stop.is_set()
                    and (time.time() - t0) < fault_deadline
                ):
                    self._sleep(2)
                    waited += 2
        finally:
            # Never leave the cluster degraded when load stops: un-pause any partitioned follower and
            # restart any node/postgres we may have just knocked over. (_recover_cluster in the settle
            # phase double-checks, but doing it here means an interrupted fault heals immediately.)
            for n in self.nodes:
                docker("unpause", n)
                if not self._container_running(n):
                    docker("start", n)
            if not self._container_running(self.pg):
                docker("start", self.pg)

    # ---- correctness ----
    def convergence(self):
        print("[verify] load stopped; recovering + settling before correctness snapshot...", flush=True)
        # 1. Recover any lingering fault (un-pause/partition, restart killed node/postgres) so the
        #    cluster is free to re-elect and reconcile.
        self._recover_cluster()
        report = {"nodes": {}}
        # Determine durable head target = max durable_max_seq observed across nodes.
        def head_of(n):
            # Newest ledger event = hash-chain head. Definitive per-node divergence signal.
            p = get_json(
                self.url(n, "/v1/ledger/events/page?limit=1&order=desc"),
                {"x-chancela-session": self.session},
            )
            if p and p.get("events"):
                e = p["events"][0]
                return e.get("seq"), e.get("hash")
            return None, None

        def sweep():
            snap = {}
            for n in self.nodes:
                h = self.node_health(n)
                v = get_json(self.url(n, "/v1/ledger/verify"), {"x-chancela-session": self.session})
                hs, hh = head_of(n)
                snap[n] = {"health": h, "verify": v, "head_seq": hs, "head_hash": hh}
            return snap

        # 2. Poll for STRICT quiescence up to settle_timeout: break the instant the cluster has a
        #    single leader AND all nodes have re-elected + fully converged to the durable head (same
        #    applied==durable==max head, lag 0, valid chains, identical head hash/seq). This is what
        #    keeps us from snapshotting mid-election right after the last fault. If the timeout
        #    elapses without that state, it is an HONEST FAIL — we do NOT extend to force green.
        target = None
        converged = False
        last = {}
        settle_start = time.time()
        settle_deadline = settle_start + self.settle_timeout
        settle_seconds = None
        while True:
            last = sweep()
            converged, target = self._strict_converged(last)
            if converged:
                settle_seconds = round(time.time() - settle_start, 2)
                print(f"[settle] cluster quiesced after {settle_seconds}s (single leader + converged)", flush=True)
                break
            if time.time() >= settle_deadline:
                settle_seconds = round(time.time() - settle_start, 2)
                print(
                    f"[settle] TIMEOUT after {settle_seconds}s (limit {self.settle_timeout}s) — "
                    "cluster did not reach single-leader + full convergence",
                    flush=True,
                )
                break
            time.sleep(self.settle_poll)

        # Build the report from the last (settled, or timed-out) sweep.
        heads = set()
        verify_lengths = set()
        head_hashes = set()
        head_seqs = set()
        all_valid = True
        leaders_final = 0
        for n, s in last.items():
            h, v = s["health"], s["verify"]
            c = (h or {}).get("cluster") or {}
            report["nodes"][n] = {
                "role": c.get("role"),
                "applied_seq": c.get("applied_seq"),
                "durable_max_seq": c.get("durable_max_seq"),
                "lag": c.get("lag"),
                "verify_valid": (v or {}).get("valid"),
                "verify_length": (v or {}).get("length"),
                "verify_error": (v or {}).get("error"),
                "head_seq": s.get("head_seq"),
                "head_hash": s.get("head_hash"),
            }
            if c.get("role") == "leader":
                leaders_final += 1
            if c.get("durable_max_seq") is not None:
                heads.add(c["durable_max_seq"])
            if v is not None:
                verify_lengths.add(v.get("length"))
                if not v.get("valid"):
                    all_valid = False
            if s.get("head_hash") is not None:
                head_hashes.add(s["head_hash"])
            if s.get("head_seq") is not None:
                head_seqs.add(s["head_seq"])

        checks = {
            "single_leader_at_end": leaders_final == 1,
            "no_multi_leader_ever": self.multi_leader_violations == 0,
            "all_nodes_agree_durable_head": len(heads) == 1,
            "all_nodes_same_verify_length": len(verify_lengths) == 1,
            "all_nodes_same_head_hash": len(head_hashes) == 1,
            "all_nodes_same_head_seq": len(head_seqs) == 1,
            "all_chains_valid": all_valid,
            "followers_converged_to_durable_head": converged,
            "durable_head_target": target,
            "head_hash": next(iter(head_hashes)) if len(head_hashes) == 1 else sorted(head_hashes),
        }
        report["checks"] = checks
        report["converged"] = converged
        # Settle metrics: how long the post-load re-election + convergence took (or that it timed out).
        report["settle"] = {
            "settle_seconds": settle_seconds,
            "settle_timeout_s": self.settle_timeout,
            "fault_stop_margin_s": self.fault_stop_margin,
            "settled": converged,
            "timed_out": not converged,
        }
        return report

    def run(self):
        # docker sanity
        rc, out, err = docker("version", "--format", "{{.Server.Version}}")
        print(f"[env] docker server {out or err}", flush=True)
        self.bootstrap()
        threads = []
        for w in range(int(os.environ.get("SOAK_WRITERS", "6"))):
            t = threading.Thread(target=self.writer_thread, args=(w,), daemon=True)
            t.start()
            threads.append(t)
        mon = threading.Thread(target=self.leader_monitor, daemon=True)
        mon.start()
        chaos = threading.Thread(target=self.chaos_thread, daemon=True)
        chaos.start()

        start = time.time()
        # periodic progress
        while time.time() - start < self.duration:
            time.sleep(15)
            with self.lock:
                ok, fail = self.writes_ok, self.writes_fail
            el = int(time.time() - start)
            print(f"[t+{el}s] writes_ok={ok} writes_fail={fail} tput={ok/max(1,el):.1f}/s", flush=True)

        print("[soak] duration elapsed; stopping load", flush=True)
        self.stop.set()
        for t in threads:
            t.join(timeout=5)
        chaos.join(timeout=5)
        mon.join(timeout=5)

        report = self.convergence()
        elapsed = time.time() - start
        with self.lock:
            summary = {
                "duration_s": round(elapsed, 1),
                "writers": len(threads),
                "writes_ok": self.writes_ok,
                "writes_fail": self.writes_fail,
                "throughput_per_s": round(self.writes_ok / max(1, elapsed), 2),
                "status_counts": {str(k): v for k, v in self.status_counts.items()},
                "redirects_followed": self.redirects,
                "multi_leader_violations": self.multi_leader_violations,
                "settle_seconds": report.get("settle", {}).get("settle_seconds"),
                "settle_timed_out": report.get("settle", {}).get("timed_out"),
                "faults": self.faults,
                "errors_sample": self.errors_sample,
                "convergence": report,
            }
        with open(self.metrics_out, "w") as f:
            json.dump(summary, f, indent=2)
        print("==== SOAK SUMMARY ====", flush=True)
        print(json.dumps(summary, indent=2), flush=True)

        ch = report["checks"]
        no_divergence = (
            ch["all_nodes_agree_durable_head"]
            and ch["all_nodes_same_verify_length"]
            and ch["all_nodes_same_head_hash"]
            and ch["all_nodes_same_head_seq"]
            and ch["all_chains_valid"]
        )
        passed = (
            no_divergence
            and ch["single_leader_at_end"]
            and ch["no_multi_leader_ever"]
            and ch["followers_converged_to_durable_head"]
            and self.writes_ok > 0
        )
        summary["ledger_divergence"] = not no_divergence
        summary["correctness_pass"] = passed
        # rewrite metrics with the verdict included
        with open(self.metrics_out, "w") as f:
            json.dump(summary, f, indent=2)
        print(f"==== LEDGER_DIVERGENCE: {'YES' if not no_divergence else 'NO'} ====", flush=True)
        print(f"==== CORRECTNESS: {'PASS' if passed else 'FAIL'} ====", flush=True)
        return 0 if passed else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", required=True, help="comma list of app container hostnames")
    ap.add_argument("--postgres-container", required=True)
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--duration", type=int, default=1800)
    # Quiesce/settle: stop new faults this long before load ends, then poll up to settle-timeout for
    # a single leader + full convergence before the final snapshot. Env-overridable for soak.sh.
    ap.add_argument(
        "--fault-stop-margin",
        type=int,
        default=int(os.environ.get("SOAK_FAULT_STOP_MARGIN", "30")),
    )
    ap.add_argument(
        "--settle-timeout",
        type=int,
        default=int(os.environ.get("SOAK_SETTLE_SECONDS", "90")),
    )
    ap.add_argument("--metrics-out", default="/tmp/soak-metrics.json")
    a = ap.parse_args()
    sys.exit(Soak(a).run())


if __name__ == "__main__":
    main()
