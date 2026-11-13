#!/usr/bin/env python3
"""
Decentralized Multi-Port HQ-FS Client Node Engine
Extracted and refactored from recent decentralized research implementation.
Simulates independent client nodes connecting across separate TCP ports,
executing Feldman DKG, RLK share generation, and HQ-FS partial decryption with ZKP.
"""

import os
import sys
import time
import math
import socket
import argparse
import threading
import logging
from collections import defaultdict
import numpy as np

# Import unified crypto & protocol components from tool
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tool import (
    RNSRing, PlaintextNTTHelper, get_ntt_primes, modinv_jit,
    decode_vec, HQFSSystem, DecentralizedClientNode,
    send_msg, recv_msg
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s")

# Global synchronizations for simulating N client nodes in one host
compute_semaphore = threading.Semaphore(16)
shared_lock = threading.Lock()
local_C_coeffs_global = None
local_acc_s = None
local_acc_e = None
dkg_dealer_barrier = None


def client_worker(server_ip, port, node_index, total_ports, is_malicious=False, data_dir="./node_data"):
    thread_id = f"Node-{node_index:03d}"
    threading.current_thread().name = thread_id

    # 1. 建立 TCP 連線
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    retries = 20
    while retries > 0:
        try:
            sock.connect((server_ip, port))
            break
        except ConnectionRefusedError:
            retries -= 1
            time.sleep(0.2)
    if retries == 0:
        logging.error(f"Failed to connect to {server_ip}:{port}")
        return

    # 2. 接收全域 CRS 參數
    init_msg = recv_msg(sock)
    assert init_msg["type"] == "INIT_PARAMS"
    assigned_id = init_msg["node_id"]
    threshold_t = init_msg["threshold_t"]
    total_n = init_msg["total_n"]
    A_global = init_msg["A_global"]
    A_crs_global = init_msg["A_crs_global"]
    d = init_msg.get("d", 16)
    T = init_msg.get("T", 65537)

    # 構造環管理器
    start_bit = 30 if d >= 128 else 20
    all_primes = get_ntt_primes(19, start_bit, d)
    q_primes = all_primes[:6]
    p_primes = all_primes[6:]
    R = RNSRing(d, q_primes, p_primes, T)
    NTT = PlaintextNTTHelper(d, T)
    p_zkp = int(R.P_q[0]) * int(R.P_q[1])

    # 3. 初始化節點並執行 DKG Dealer
    with compute_semaphore:
        node = DecentralizedClientNode(assigned_id, threshold_t, total_n, R, A_global, A_crs_global, p_zkp=p_zkp)
        pub_key, sub_s, sub_e, C_coeffs = node.execute_dkg_dealer_phase()

    with shared_lock:
        global local_C_coeffs_global, local_acc_s, local_acc_e
        if local_C_coeffs_global is None:
            local_C_coeffs_global = [[R.zero() for _ in range(node.m_glwe)] for _ in range(threshold_t)]
        for deg in range(threshold_t):
            for k in range(node.m_glwe):
                local_C_coeffs_global[deg][k] = R.add(local_C_coeffs_global[deg][k], C_coeffs[deg][k])
        for target_j in range(1, total_n + 1):
            for dim in range(node.n_glwe):
                if local_acc_s[target_j][dim] is None:
                    local_acc_s[target_j][dim] = sub_s[target_j][dim]
                else:
                    local_acc_s[target_j][dim] = R.add(local_acc_s[target_j][dim], sub_s[target_j][dim])
            for dim in range(node.m_glwe):
                if local_acc_e[target_j][dim] is None:
                    local_acc_e[target_j][dim] = sub_e[target_j][dim]
                else:
                    local_acc_e[target_j][dim] = R.add(local_acc_e[target_j][dim], sub_e[target_j][dim])

    del sub_s, sub_e, C_coeffs

    send_msg(sock, {
        "type": "DKG_DEALER_SUBMIT",
        "node_id": assigned_id,
        "pub_key": pub_key
    })
    del pub_key

    # 等待本地節點完成累加
    dkg_dealer_barrier.wait()

    # 4. 接收廣播承諾並執行接收者驗證
    routed_msg = recv_msg(sock)
    assert routed_msg["type"] in ("DKG_ROUTED_COMMITMENTS", "DKG_ROUTED_SHARES")

    with compute_semaphore:
        commitment = node.execute_dkg_receiver_phase(
            local_acc_s[assigned_id],
            local_acc_e[assigned_id],
            local_C_coeffs_global
        )
        node.save_to_json(data_dir=data_dir)

    send_msg(sock, {
        "type": "DKG_FINAL_COMMITMENT",
        "node_id": assigned_id,
        "commitment": commitment
    })

    # 5. 分散式 RLK 份額計算
    rlk_req = recv_msg(sock)
    assert rlk_req["type"] == "RLK_GEN_REQ"
    A_rlk_global = rlk_req["A_rlk"]

    with compute_semaphore:
        node_rlk_shares = node.compute_collective_rlk_share(A_rlk_global)

    send_msg(sock, {
        "type": "RLK_SHARE_SUBMIT",
        "node_id": assigned_id,
        "rlk_shares": node_rlk_shares
    })
    del node_rlk_shares, A_rlk_global

    # 6. 等待門限解密請求
    dec_req = recv_msg(sock)
    assert dec_req["type"] == "DECRYPT_REQ"
    u = dec_req["u"]

    with compute_semaphore:
        user_state = DecentralizedClientNode.load_from_json(assigned_id, data_dir=data_dir)
        p_share, proof = HQFSSystem.partial_decrypt_with_multi_hq_fs(
            u, user_state["final_s"], user_state["final_e"], A_crs_global, user_state["zkp_commitment"],
            R, p_zkp, node.m_glwe, node.n_glwe
        )

    if is_malicious:
        logging.warning(f"🚨 [Malicious Node-{assigned_id:03d}] Tampering with partial share and ZKP proof!")
        p_share[0][0] = (p_share[0][0] + 999999) % int(R.P_q[0])
        proof["z_s_limbs"][0][0][0] = (proof["z_s_limbs"][0][0][0] + 999999) % int(R.P_q[HQFSSystem.K_IDXs[0]])

    send_msg(sock, {
        "type": "DECRYPT_RESP",
        "node_id": assigned_id,
        "p_share": p_share,
        "proof": proof
    })

    # 7. 若為 Node 1，接收最終盲化結果並在本地還原解碼
    if assigned_id == 1:
        final_msg = recv_msg(sock)
        if final_msg and final_msg["type"] == "FINAL_DEC_RESULT":
            v_sub_agg = final_msg["v_sub_agg"]
            Delta_int = final_msg["Delta_int"]

            dec_scaled = decode_vec(v_sub_agg, R, NTT, R.Q_big // T, T)
            inv_delta_T = modinv_jit(Delta_int % T, T)
            dec = (dec_scaled * inv_delta_T) % T

            logging.info(f"🎉 [Client Node 1 Decrypted Result][:8]: {dec[:8]}")
            logging.info("Private result successfully retrieved on Client without Server knowing plaintext!")

    sock.close()


def run_client(server_ip="127.0.0.1", base_port=10001, total_ports=10, num_hackers=2, data_dir="./node_data"):
    global local_C_coeffs_global, local_acc_s, local_acc_e, dkg_dealer_barrier
    local_C_coeffs_global = None
    local_acc_s = defaultdict(lambda: [None for _ in range(2)])
    local_acc_e = defaultdict(lambda: [None for _ in range(3)])
    dkg_dealer_barrier = threading.Barrier(total_ports)

    # 隨機挑選惡意節點 (排除 Node 1 方便打印結果)
    if num_hackers > 0:
        candidates = list(range(2, total_ports + 1))
        hacker_indices = set(np.random.choice(candidates, size=min(num_hackers, len(candidates)), replace=False))
    else:
        hacker_indices = set()

    logging.info(f"=== Starting {total_ports} Client Nodes connecting to {server_ip}:{base_port}..{base_port+total_ports-1} ===")
    logging.info(f"Malicious hackers configured: {sorted(list(hacker_indices))}")

    threads = []
    for i in range(total_ports):
        node_id = i + 1
        port = base_port + i
        is_mal = (node_id in hacker_indices)
        t = threading.Thread(
            target=client_worker,
            args=(server_ip, port, node_id, total_ports, is_mal, data_dir),
            name=f"Thread-Client-{node_id}"
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()
    logging.info(f"All {total_ports} client workers finished cleanly.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Port Decentralized HQ-FS Client")
    parser.add_argument("--server_ip", default="127.0.0.1", help="Coordinator Server IP")
    parser.add_argument("--base_port", type=int, default=10001, help="Starting port number")
    parser.add_argument("--total_ports", type=int, default=10, help="Total number of nodes")
    parser.add_argument("--num_hackers", type=int, default=2, help="Number of malicious nodes to simulate")
    parser.add_argument("--data_dir", default="./node_data", help="Local directory for JSON persistence")
    args = parser.parse_args()

    run_client(
        server_ip=args.server_ip,
        base_port=args.base_port,
        total_ports=args.total_ports,
        num_hackers=args.num_hackers,
        data_dir=args.data_dir
    )
