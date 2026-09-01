#!/usr/bin/env bash
# Obtient un jeton de rafraîchissement Cognito pour l'intégration Veolia.
#
# À lancer depuis un poste habituel (celui d'où vous consultez le portail) :
# l'authentification adaptative de Cognito n'y réclame pas de code SMS, alors
# qu'elle le fait depuis un serveur dont elle ne connaît pas le contexte.
#
# Le jeton s'affiche à l'écran pour être collé dans le config flow de Home
# Assistant. C'est un identifiant à part entière : ne le partagez pas.
set -u

CLIENT_ID="${VEOLIA_CLIENT_ID:-19bjc8ldefie683n889iiubjc8}"  # Eau de Toulouse Métropole
# Portail national : 3kghade1fg54739kj8pkbova8j
# La table complète vit dans veolia_api/portals.py.

read -rp "Email Veolia : " VEOLIA_USER
read -rsp "Mot de passe : " VEOLIA_PASS; echo
export VEOLIA_USER VEOLIA_PASS CLIENT_ID

python3 - <<'PY'
import json, os, sys, urllib.error, urllib.request

req = urllib.request.Request(
    "https://cognito-idp.eu-west-3.amazonaws.com/",
    data=json.dumps({
        "ClientId": os.environ["CLIENT_ID"],
        "AuthFlow": "USER_PASSWORD_AUTH",
        "AuthParameters": {
            "USERNAME": os.environ["VEOLIA_USER"],
            "PASSWORD": os.environ["VEOLIA_PASS"],
        },
    }).encode(),
    headers={
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    },
)
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        body = json.load(r)
except urllib.error.HTTPError as e:
    body = json.load(e)

if body.get("ChallengeName"):
    print(f"\nCognito réclame « {body['ChallengeName']} » depuis ce poste.",
          file=sys.stderr)
    print("Relancez depuis la machine d'où vous consultez habituellement le "
          "portail.", file=sys.stderr)
    raise SystemExit(1)

token = (body.get("AuthenticationResult") or {}).get("RefreshToken")
if not token:
    print(f"\nRéponse inattendue (clés : {sorted(body)})", file=sys.stderr)
    raise SystemExit(1)

print("\n=== Jeton de rafraîchissement — à coller dans Home Assistant ===\n")
print(token)
PY

unset VEOLIA_USER VEOLIA_PASS
