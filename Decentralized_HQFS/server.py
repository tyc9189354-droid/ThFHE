#!/usr/bin/env python3
"""
Decentralized Multi-Port HQ-FS Server / Coordinator Node
Extracted and refactored from recent decentralized research implementation.
Utilizes C-accelerated RNS-GLWE, Tree-Bisection ZKP Verification, and Committee Lagrange Reconstruction.
"""

import os
import sys
import time
import math
import socket
import select
import struct
import pickle
import argparse
import logging
import numpy as np

# Import unified crypto & protocol components from tool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool import (
    RNSRing, PlaintextNTTHelper, get_ntt_primes, modinv_jit,
    small_poly, get_flood_noise_poly, uniform_poly,
    embed_vec, decode_vec, encrypt, add, mul,
    HQFSVerifier, compute_committee_lagrange,
    send_msg, recv_msg, broadcast_msg
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def run_multi_port_server(host="0.0.0.0", base_port=10001, total_ports=10, threshold_t=6, d=16, T=65537):
    """
    開啟 total_ports 個獨立的 Socket Ports (base_port ~ base_port + total_ports - 1)，
    每個 Client 連線至單一專屬 Port。
    Server 僅充當密文運算中心與聚合驗證節點，不包含任何 Client 端秘密金鑰。
    """
    logging.info(f"=== Starting TFHE Coordinator Server on {total_ports} ports (Port {base_port} ~ {base_port + total_ports - 1}) ===")
    logging.info(f"Target Threshold: t={threshold_t} / N={total_ports}, d={d}, T={T}")

    # 1. 綁定 Server Sockets
    server_sockets = {}
    for i in range(total_ports):
        node_id = i + 1
        port = base_port + i
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        server_sockets[s] = (node_id, port)

    logging.info(f"Successfully bound {total_ports} listening ports. Waiting for clients to connect...")

    # 2. 等待各 Client 連入專屬 Port
    client_conns = {}
    sockets_to_watch = list(server_sockets.keys())

    while len(client_conns) < total_ports:
        readable, _, _ = select.select(sockets_to_watch, [], [], 1.0)
        for s in readable:
            conn, addr = s.accept()
            node_id, port = server_sockets[s]
            client_conns[node_id] = conn
            sockets_to_watch.remove(s)
            logging.info(f"Node {node_id:3d} connected on Port {port} from {addr} ({len(client_conns)}/{total_ports})")

    # 3. 初始化 RNS 環與參數
    n_glwe = 2
    m_glwe = 3
    start_bit = 48 if total_ports > 50 else 30
    all_primes = get_ntt_primes(19, start_bit, d)
    q_primes = all_primes[:6]
    p_primes = all_primes[6:]
    R = RNSRing(d, q_primes, p_primes, T)
    NTT = PlaintextNTTHelper(d, T)
    Delta = R.Q_big // T
    p_zkp = int(R.P_q[0]) * int(R.P_q[1])

    # 廣播全域公開參數 (CRS)
    A_global = [[uniform_poly(R) for _ in range(n_glwe)] for _ in range(m_glwe)]
    A_crs_global = [[uniform_poly(R) for _ in range(n_glwe)] for _ in range(m_glwe)]

    logging.info(f"Broadcasting global CRS parameters to all {total_ports} clients...")
    for node_id, conn in client_conns.items():
        send_msg(conn, {
            "type": "INIT_PARAMS",
            "node_id": node_id,
            "threshold_t": threshold_t,
            "total_n": total_ports,
            "A_global": A_global,
            "A_crs_global": A_crs_global,
            "d": d,
            "T": T
        })

    # 4. DKG 階段：接收 Client 的公鑰與多項式承諾，同態聚合 C_coeffs_global
    logging.info("Receiving DKG public keys and commitments from clients...")
    pk_global = [R.zero() for _ in range(m_glwe)]
    C_coeffs_global = [[R.zero() for _ in range(m_glwe)] for _ in range(threshold_t)]

    for node_id, conn in client_conns.items():
        msg = recv_msg(conn)
        if msg is None:
            raise ConnectionError(f"Node {node_id} disconnected unexpectedly!")
        assert msg["type"] == "DKG_DEALER_SUBMIT"

        pub_key = msg["pub_key"]
        for k in range(m_glwe):
            pk_global[k] = R.add(pk_global[k], pub_key[k])
        c_coeffs = msg.get("C_coeffs")
        if c_coeffs is not None:
            for deg in range(threshold_t):
                for k in range(m_glwe):
                    C_coeffs_global[deg][k] = R.add(C_coeffs_global[deg][k], c_coeffs[deg][k])

    # 廣播聚合承諾
    logging.info("Broadcasting DKG_ROUTED_COMMITMENTS to all clients...")
    for target_j, conn in client_conns.items():
        send_msg(conn, {
            "type": "DKG_ROUTED_COMMITMENTS",
            "C_coeffs_global": C_coeffs_global
        })

    # 接收全部 Client 的 DKG_FINAL_COMMITMENT
    logging.info("Receiving final ZKP commitments from all clients...")
    public_commitments = {}
    for node_id, conn in client_conns.items():
        msg = recv_msg(conn)
        if msg is None:
            raise ConnectionError(f"Node {node_id} disconnected before sending DKG_FINAL_COMMITMENT!")
        assert msg["type"] == "DKG_FINAL_COMMITMENT"
        public_commitments[node_id] = msg["commitment"]

    # 5. 2-Round 協同分散式 RLK 生成 (Mouchet Collective RLK)
    logging.info(f"Initiating 2-Round Collective Distributed RLK Generation with {total_ports} clients...")
    A_rlk_global = {}
    A_rlk_crs = {}
    for a in range(n_glwe):
        for b_idx in range(n_glwe):
            A_rlk_global[(a, b_idx)] = [[uniform_poly(R) for _ in range(n_glwe)] for _ in range(R.s_q)]
            A_rlk_crs[(a, b_idx)] = [uniform_poly(R) for _ in range(R.s_q)]

    payload_r1 = pickle.dumps({"type": "RLK_R1_REQ", "A_rlk_crs": A_rlk_crs})
    packet_r1 = struct.pack(">I", len(payload_r1)) + payload_r1
    for conn in client_conns.values():
        conn.sendall(packet_r1)
    del payload_r1, packet_r1

    H_agg = {}
    for a in range(n_glwe):
        for b_idx in range(n_glwe):
            H_agg[(a, b_idx)] = [(R.zero(), R.zero()) for _ in range(R.s_q)]

    for node_id, conn in client_conns.items():
        msg = recv_msg(conn)
        if msg is None:
            raise ConnectionError(f"Node {node_id} disconnected during RLK Round 1!")
        assert msg["type"] == "RLK_R1_SUBMIT"
        r1 = msg["r1_shares"]
        for a in range(n_glwe):
            for b_idx in range(n_glwe):
                for i in range(R.s_q):
                    h0_c, h1_c = H_agg[(a, b_idx)][i]
                    h0_j, h1_j = r1[(a, b_idx)][i]
                    H_agg[(a, b_idx)][i] = (R.add(h0_c, h0_j), R.add(h1_c, h1_j))

    payload_r2 = pickle.dumps({"type": "RLK_R2_REQ", "A_rlk": A_rlk_global, "H_agg": H_agg})
    packet_r2 = struct.pack(">I", len(payload_r2)) + payload_r2
    for conn in client_conns.values():
        conn.sendall(packet_r2)
    del payload_r2, packet_r2

    logging.info(f"Gathering collective RLK Round 2 shares from all {total_ports} clients...")
    rlk = {}
    for a in range(n_glwe):
        for b_idx in range(n_glwe):
            rlk[(a, b_idx)] = [(A_rlk_global[(a, b_idx)][i], R.zero()) for i in range(R.s_q)]

    for node_id, conn in client_conns.items():
        msg = recv_msg(conn)
        if msg is None:
            raise ConnectionError(f"Node {node_id} disconnected during RLK Round 2 submission!")
        assert msg["type"] == "RLK_R2_SUBMIT"
        node_shares = msg["rlk_shares"]
        for a in range(n_glwe):
            for b_idx in range(n_glwe):
                for i in range(R.s_q):
                    av, bv = rlk[(a, b_idx)][i]
                    rlk[(a, b_idx)][i] = (av, R.add(bv, node_shares[(a, b_idx)][i]))

    del A_rlk_global, A_rlk_crs, H_agg
    logging.info("🎉 Collective Distributed Relinearization Key (RLK) successfully synthesized!")

    # 6. 雲端複合同態計算：(m1 * m2 + m3) mod T
    logging.info("Server executing homomorphic evaluation: (Enc(m1) * Enc(m2)) + Enc(m3)...")
    t0_eval = time.time()
    rng = np.random.default_rng(42)
    m1 = rng.integers(0, 16, size=d)
    m2 = rng.integers(0, 16, size=d)
    m3 = rng.integers(0, 16, size=d)

    ct1 = encrypt(m1, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe)
    ct2 = encrypt(m2, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe)
    ct3 = encrypt(m3, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe)

    ct_prod = mul(ct1, ct2, rlk, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe)
    ct_mul = add(ct_prod, ct3, A_global, pk_global, R, NTT, Delta, m_glwe, n_glwe)
    logging.info(f"Homomorphic evaluation finished in {(time.time() - t0_eval):.2f} s. Broadcasting decryption request...")

    # 7. 門限解密請求
    for node_id, conn in client_conns.items():
        send_msg(conn, {
            "type": "DECRYPT_REQ",
            "u": ct_mul[0]
        })

    submitted_data = {}
    for node_id, conn in client_conns.items():
        resp = recv_msg(conn)
        assert resp["type"] == "DECRYPT_RESP"
        submitted_data[node_id] = (resp["p_share"], resp["proof"])

    # 8. 樹狀批次 ZKP 驗證 (BFT 容錯)
    logging.info(f"Executing BFT Tree Verification across all {total_ports} client submissions...")
    t0_verify = time.time()
    valid_ids = HQFSVerifier.verify_n_tree(
        ct_mul[0], submitted_data, list(submitted_data.keys()),
        A_crs_global, public_commitments, R, p_zkp, m_glwe, n_glwe, k_idxs=[0, 1], n_branch=4
    )
    verify_ms = (time.time() - t0_verify) * 1000

    rejected_nodes = sorted(list(set(submitted_data.keys()) - set(valid_ids)))
    logging.info(f"Verification completed in {verify_ms:.2f} ms. Honest Nodes: {len(valid_ids)}/{total_ports}")
    if rejected_nodes:
        logging.warning(f"🛡️ BFT Defense Triggered! Isolated & kicked out Malicious Nodes: {rejected_nodes}")

    # 9. Lagrange 聚合與解碼還原
    if len(valid_ids) >= threshold_t:
        active_set = sorted(valid_ids)[:threshold_t]
        logging.info(f"Selected {threshold_t} honest nodes for Lagrange interpolation: {active_set}")
        lams_int_map, Delta_int = compute_committee_lagrange(active_set)
        logging.info(f"Lagrange Delta_int = {Delta_int}")

        agg_sum = [np.zeros(d, dtype=np.int64) for _ in range(R.s_q)]
        for node_id in active_set:
            part_s = submitted_data[node_id][0]
            lam_int = lams_int_map[node_id]
            for mi in range(R.s_q):
                p_qi = int(R.P_q[mi])
                lam_mod = lam_int % p_qi
                agg_sum[mi] = (agg_sum[mi] + (part_s[mi] * lam_mod) % p_qi) % p_qi

        v_scaled = [np.zeros(d, dtype=np.int64) for _ in range(R.s_q)]
        for mi in range(R.s_q):
            p_qi = int(R.P_q[mi])
            delta_mod = Delta_int % p_qi
            v_scaled[mi] = (ct_mul[1][mi] * delta_mod) % p_qi

        v_sub_agg = R.sub(v_scaled, agg_sum)
        logging.info("Server aggregation finished. Sending blinded decryption result to Client (Node 1)...")
        send_msg(client_conns[1], {
            "type": "FINAL_DEC_RESULT",
            "v_sub_agg": v_sub_agg,
            "Delta_int": Delta_int
        })
    else:
        logging.error(f"Insufficient honest nodes! Got {len(valid_ids)}, required {threshold_t}.")

    # 10. 關閉連線
    logging.info("Closing client connections...")
    for node_id, conn in client_conns.items():
        try:
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(1.0)
            while conn.recv(1024): pass
        except Exception:
            pass
        finally:
            conn.close()
    for s in server_sockets.keys():
        s.close()
    logging.info("All server connections closed cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Port Decentralized HQ-FS Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind")
    parser.add_argument("--base_port", type=int, default=10001, help="Starting port number")
    parser.add_argument("--total_ports", type=int, default=10, help="Total number of nodes/ports")
    parser.add_argument("--threshold_t", type=int, default=6, help="Threshold t")
    parser.add_argument("--d", type=int, default=16, help="Polynomial degree (default: 16 for fast testing, 8192 for full scale)")
    parser.add_argument("--T", type=int, default=65537, help="Plaintext modulus (default: 65537)")
    args = parser.parse_args()

    run_multi_port_server(
        host=args.host,
        base_port=args.base_port,
        total_ports=args.total_ports,
        threshold_t=args.threshold_t,
        d=args.d,
        T=args.T
    )
