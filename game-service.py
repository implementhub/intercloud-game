#!/usr/bin/env python3

import json
import ssl
import subprocess
import time
import urllib.request
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import os
import secrets
import hashlib
from http.server import ThreadingHTTPServer
import logging

# =========================
# Logging Setup
# =========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger("game-service")



# =========================
# Global State
# =========================

current_game = {}

CERTS_PATH = "intercloud-game/certs"
MOVES = ["rock", "paper", "scissors"]
game_active = False
target_url = ""

games = {}   # game_id -> game state
scores = {}  # spiffe_id -> {wins, losses}



# =========================
# Crypto Helpers
# =========================

def make_commitment(move, salt):
    return hashlib.sha256(f"{move}{salt}".encode()).hexdigest()

def verify_commitment(move, salt, commitment):
    return make_commitment(move, salt) == commitment


# =========================
# Game Logic
# =========================

def get_spiffe_id_opponent(self):
    peer_cert = self.connection.getpeercert()
    san = None
    if peer_cert and 'subjectAltName' in peer_cert:
        for entry in peer_cert['subjectAltName']:
            if entry[0] == 'URI':
                san = entry[1]
                return san

def get_own_spiffe_id():
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', f'{CERTS_PATH}/svid.pem', '-text', '-noout'],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.split('\n'):
            if 'URI:spiffe://' in line:
                return line.split('URI:')[1].strip()
    except Exception as e:
        return "unknown"
    return "unknown"

# --------- decide game winner
def decide(a, b):
    if a == b:
        return "tie"

    wins = {
        ("rock", "scissors"),
        ("scissors", "paper"),
        ("paper", "rock"),
    }
    return "win" if (a, b) in wins else "loss"

def save_score(result, peer_id):
    # Score speichern
    if peer_id not in scores:
        scores[peer_id] = {"wins": 0, "losses": 0}

    if result == "win":
        scores[peer_id]["wins"] += 1
    else:
        scores[peer_id]["losses"] += 1



# =========================
# HTTP Handler
# =========================

class PingHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        client_ip = self.client_address[0]
        
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body)

        logger.info(f"[REQUEST] {client_ip} → {data.get('type')}")

        if data["type"] == "challenge":
            self.handle_challenge(data, get_spiffe_id_opponent(self))

        elif data["type"] == "response":
            self.handle_response(data, get_spiffe_id_opponent(self))

        elif data["type"] == "reveal":
            self.handle_reveal(data, get_spiffe_id_opponent(self))

        else:
            logger.warning(f"[WARNING] Unknown message type: {data.get('type')}")
            self.send_response(400)
            self.end_headers()


    def handle_challenge(self, data, peer_id):
        logger.info(f"[GAME] Challenge received from {peer_id}")
        logger.info(f"[COMMIT] Opponent commitment: {data['commitment'][:12]}...")

        move = secrets.choice(MOVES)
        logger.info(f"[MOVE] Generated response move: {move}")

        current_game.clear()
        current_game.update({
            "commitment": data["commitment"],
            "own_move": move
        })

        send_to_peer(target_url, "/response", {
            "type": "response",
            "move": move
        })

        logger.info("[GAME] Response sent")

        self.respond({"status": "ok"})


    def handle_response(self, data, peer_id):
        if not current_game:
            logger.warning("[GAME] No active round")
            self.respond({"status": "ignored"})
            return

        logger.info(f"[RESPONSE] Opponent move received: {data['move']}")

        current_game["opponent_move"] = data["move"]

        logger.info("[REVEAL] Sending reveal")

        #breakpoint()

        response = send_to_peer(target_url, "/reveal", {
            "type": "reveal",
            "move": current_game["own_move"],
            "salt": current_game["own_salt"]
        })

        status = json.loads(response.decode('utf-8'))["status"]
        if status == "win":
            save_score("loss", peer_id)
        elif status == "loss":
            save_score("win", peer_id)
        elif status == "tie":
            logger.info("[GAME] Tie detected → replay required")

        print(f"[SCORE] {peer_id}: {scores[peer_id]}")

        global game_active
        game_active = False

        self.respond({"status": "ok"})


    def handle_reveal(self, data, peer_id):
        logger.info(f"[REVEAL] Reveal received from {peer_id}")
        logger.info(f"[REVEAL] Opponent move: {data['move']}")

        if not verify_commitment(
            data["move"],
            data["salt"],
            current_game["commitment"]
        ):
            logger.warning("[SECURITY] Commitment verification FAILED")
            self.respond({"status": "invalid"})
            return

        opponent_move = data["move"]
        own_move = current_game["own_move"]

        result = decide(own_move, opponent_move)
        print(f"[RESULT] {own_move} vs {opponent_move} → {result}")
            
        save_score(result, peer_id)

        print(f"[SCORE] {peer_id}: {scores[peer_id]}")

        self.respond({"status": result})


    def respond(self, payload):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def log_message(self, format, *args):
        pass



# =========================
# Networking
# =========================

def send_to_peer(target_url, path, payload):
    print("send_to_peer")

    context = ssl.create_default_context()
    context.load_cert_chain(f'{CERTS_PATH}/svid.pem', f'{CERTS_PATH}/svid_key.pem')
    context.load_verify_locations(f'{CERTS_PATH}/svid_bundle.pem')
    context.check_hostname = False

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{target_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, context=context) as r:
        response = r.read()
    return response


# =========================
# Game Flow
# =========================

def start_new_round(target_url, peer_id):
    global game_active
    game_active = True

    move = secrets.choice(MOVES)
    salt = secrets.token_hex(8)
    commitment = make_commitment(move, salt)

    logger.info("[GAME] New round started")
    logger.info(f"[MOVE] Selected move: {move}")
    logger.info(f"[COMMIT] Commitment created: {commitment[:12]}...")

    current_game.clear()
    current_game.update({
        "own_move": move,
        "own_salt": salt,
        "commitment": commitment,
        "opponent_move": None
    })

    response = send_to_peer(target_url, "/challenge", {
        "type": "challenge",
        "commitment": commitment
    })

    print(f"[CLIENT] Received response: {response.decode()}")


def start_server(port, name):

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(f'{CERTS_PATH}/svid.pem', f'{CERTS_PATH}/svid_key.pem')
    context.load_verify_locations(f'{CERTS_PATH}/svid_bundle.pem')
    context.verify_mode = ssl.CERT_REQUIRED

    server = ThreadingHTTPServer(('localhost', port), PingHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    
    own_id = get_own_spiffe_id()
    logger.info(f"[BOOT] {name} started on port {port} My SPIFFE ID: {own_id}")
    server.serve_forever()


def start_game(target_url, name):
    own_id = get_own_spiffe_id()
    print(f"[{name}] My SPIFFE ID: {own_id}")
    time.sleep(2)

    logger.info(f"[BOOT] Player started → {args.name}")
    
    action = ""
    while action != "x" and not game_active:
        try:
            action = input("n = new game | x = exit: ")
            if action == "n":
                start_new_round(target_url, name)
        except Exception as e:
            print(f"[{name}] ✗ Game start failed: {e}")

        time.sleep(5)
    
    logger.info("[SYSTEM] Shutting down")


class PublicScoreHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path != "/score":
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        self.wfile.write(json.dumps({
            "scores": scores
        }).encode())


def start_public_https_server(httpport):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        "/home/azureuser/acme-lab/04-finalize/http-certificate.pem",
        "/home/azureuser/acme-lab/04-finalize/domain-key.pem"
    )

    server = ThreadingHTTPServer(("0.0.0.0", httpport), PublicScoreHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[PUBLIC] HTTPS score endpoint listening on :{httpport}")
    server.serve_forever()


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--target', type=str, required=True)
    parser.add_argument('--name', type=str, required=True)
    parser.add_argument('--httpport', type=int, default=443)
    args = parser.parse_args()

    if not all(os.path.exists(f'{CERTS_PATH}/{f}') for f in ['svid.pem', 'svid_key.pem', 'svid_bundle.pem']):
        print("Error: Certificate files not found. Run spiffe-helper first.")
        return 1
    
    ###### START HTTP Server
    print("Start HTTP server")
    threading.Thread(
        target=start_public_https_server,
        args=(args.httpport,),
        daemon=True
    ).start()

    ####### Start Game Server
    threading.Thread(target=start_server, args=(args.port, args.name), daemon=True).start()
    time.sleep(1)
    global target_url
    target_url = args.target

    start_game(args.target, args.name)

if __name__ == '__main__':
    main()
