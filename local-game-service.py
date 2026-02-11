#!/usr/bin/env python3

import json
import ssl
import time
import urllib.request
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import secrets
import hashlib
from http.server import ThreadingHTTPServer


# game state
current_game = {}


MOVES = ["rock", "paper", "scissors"]
gameActive = False
target_url = ""

games = {}   # game_id -> game state
scores = {}  # spiffe_id -> {wins, losses}

# ---------- Crypto helpers ----------

def make_commitment(move, salt):
    return hashlib.sha256(f"{move}{salt}".encode()).hexdigest()

def verify_commitment(move, salt, commitment):
    return make_commitment(move, salt) == commitment


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


# ------------------ HTTP Handler ------------------

class PingHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        print("receive POST")
        
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body)

        print(f"Received type: {data.get('type')}")

        if data["type"] == "challenge":
            print("handle type challenge")
            self.handle_challenge(data, "<peer_id>")

        elif data["type"] == "response":
            print("handle type response")
            self.handle_response(data, "<peer_id>")

        elif data["type"] == "reveal":
            self.handle_reveal(data, "<peer_id>")

        else:
            print("Type nicht gefunden")
            self.send_response(400)
            self.end_headers()


    def handle_challenge(self, data, peer_id):
        print("handle_challenge...")
        move = secrets.choice(MOVES)
        commitment = data["commitment"]

        print(f"[SERVER] My move: {move}")

        current_game.clear()
        current_game.update({
            "commitment": data["commitment"],
            "own_move": move
        })

        send_to_peer(target_url, "/response", {
            "type": "response",
            "move": move
        })

        self.respond({"status": "ok"})


    def handle_response(self, data, peer_id):
        print("handle_response...")

        if not current_game:
            print("⚠️ No active game")
            self.respond({"status": "ignored"})
            return

        current_game["opponent_move"] = data["move"]

        print(f"[CLIENT] Response received → revealing move")

        #breakpoint()

        response = send_to_peer(target_url, "/reveal", {
            "type": "reveal",
            "move": current_game["own_move"],
            "salt": current_game["own_salt"]
        })

        status = json.loads(response.decode('utf-8'))["status"]
        if status == "win":
            save_score("loss", peer_id)
        else:
            save_score("win", peer_id)

        print(f"[SCORE] {peer_id}: {scores[peer_id]}")

        global gameActive
        gameActive = False

        self.respond({"status": "ok"})


    def handle_reveal(self, data, peer_id):
        print("handle_reveal...")

        if not verify_commitment(
            data["move"],
            data["salt"],
            current_game["commitment"]
        ):
            self.respond({"status": "invalid"})
            return

        # Commitment prüfen
        if not verify_commitment(
            data["move"],
            data["salt"],
            current_game["commitment"]
        ):
            print("❌ Commitment verification failed")
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
        print("respond..")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def do_GET(self):
        if self.path == '/ping':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()

            san = "der andere"
            '''
            peer_cert = self.connection.getpeercert()
            san = None
            if peer_cert and 'subjectAltName' in peer_cert:
                for entry in peer_cert['subjectAltName']:
                    if entry[0] == 'URI':
                        san = entry[1]
                        break
            '''
            response_msg = f'pong from {san}' if san else 'pong'
            self.wfile.write(response_msg.encode())
            
            print(f"✓ Received ping from {self.client_address[0]} - Peer: {san}")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

'''
def get_own_spiffe_id():
    try:
        result = subprocess.run(
            ['openssl', 'x509', '-in', 'certs/svid.pem', '-text', '-noout'],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.split('\n'):
            if 'URI:spiffe://' in line:
                return line.split('URI:')[1].strip()
    except Exception as e:
        return "unknown"
    return "unknown"
'''


def start_server(port, name):
    '''
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain('certs/svid.pem', 'certs/svid_key.pem')
    context.load_verify_locations('certs/svid_bundle.pem')
    context.verify_mode = ssl.CERT_REQUIRED
    '''

    server = ThreadingHTTPServer(('localhost', port), PingHandler)
    #server.socket = context.wrap_socket(server.socket, server_side=True)
    
    #own_id = get_own_spiffe_id()
    #print(f"[{name}] Server started (SPIFFE ID: {own_id})")
    print(f"[{name}] Listening on port {port}")
    server.serve_forever()


def send_to_peer(target_url, path, payload):
    print("send_to_peer")

    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{target_url}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as r:
        response = r.read()
    return response

# ---------- Game flow ----------
def start_new_round(target_url, peer_id):
    print("start_new_round")
    global gameActive
    gameActive = True
    move = secrets.choice(MOVES)
    salt = secrets.token_hex(8)
    commitment = make_commitment(move, salt)

    print(f"[CLIENT] New round → {move}")

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


def sendPing(target_url, name):
    req = urllib.request.Request(f'{target_url}/ping') 
    with urllib.request.urlopen(req, timeout=5) as response:
        result = response.read().decode()
        print(f"[{name}] ✓ Cross-domain ping successful!")
        print(f"[{name}]   → Response: {result}")



def ping_target(target_url, name):
    #own_id = get_own_spiffe_id()
    print(f"[{name}] My SPIFFE ID: {'<own_id>'}")
    time.sleep(2)
    
    action = ""
    while action != "x" and not gameActive:
        try:
            print("n für neues spiel beginnen und x für beenden")
            action = input("Was möchtest du tun? n/x: ")
            if action == "n":
                #sendPing(target_url, name)
                start_new_round(target_url, name)
        except Exception as e:
            print(f"[{name}] ✗ Ping failed: {e}")

        time.sleep(5)
    
    print("Spiel beendet")

'''
    while True:
        try:
            context = ssl.create_default_context()
            context.load_cert_chain('certs/svid.pem', 'certs/svid_key.pem')
            context.load_verify_locations('certs/svid_bundle.pem')
            context.check_hostname = False

            req = urllib.request.Request(f'{target_url}/ping')
            with urllib.request.urlopen(req, context=context, timeout=5) as response:
                result = response.read().decode()
                print(f"[{name}] ✓ Cross-domain ping successful!")
                print(f"[{name}]   → Response: {result}")

        except Exception as e:
            print(f"[{name}] ✗ Ping failed: {e}")

        time.sleep(5)
'''

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

def start_public_https_server():
    #context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #context.load_cert_chain(
    #    "/home/azureuser/acme-lab/04-finalize/http-certificate.pem",
    #    "/home/azureuser/acme-lab/04-finalize/http-private-key.pem"
    #)

    server = ThreadingHTTPServer(("0.0.0.0", 443), PublicScoreHandler)
    #server.socket = context.wrap_socket(server.socket, server_side=True)

    print("[PUBLIC] HTTPS score endpoint listening on :443")
    server.serve_forever()



def main():

    ###### START HTTP Server
    print("Start HTTP server")
    threading.Thread(
    target=start_public_https_server,
    daemon=True
        ).start()

    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--target', type=str, required=True)
    parser.add_argument('--name', type=str, required=True)
    args = parser.parse_args()

    #if not all(os.path.exists(f'certs/{f}') for f in ['svid.pem', 'svid_key.pem', 'svid_bundle.pem']):
        #print("Error: Certificate files not found. Run spiffe-helper first.")
        #return 1

    threading.Thread(target=start_server, args=(args.port, args.name), daemon=True).start()
    time.sleep(1)
    
    global target_url
    target_url = args.target
    ping_target(args.target, args.name)

if __name__ == '__main__':
    main()
