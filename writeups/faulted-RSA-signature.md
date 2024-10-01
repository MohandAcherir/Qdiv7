# Faulted RSA signature attack

Le challenge commence par "Nous savons que les signatures ont été générées par un service en Go 1.5.1 sur une architecture
32 bits".\
Après avoir médité sur cette ligne, quelques recherches sur la version 1.5.1 de Go ont révélé que ce
service est susceptible à des erreurs dans le processus d’exponentiation.\
Ensuite, il nous est donné dix signatures, une clé publique RSA et un message chiffré avec la clé privée correspondante qu'on ne
connait pas.

La clé publique:
```
-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyj+K5YrxLR0K1kurP0K
GtOgXhnBKAkMJgiGu2OrbjRXHy0uATxajodcWbsKSjLuAgsDiO17ADYHBisIfiqo
/eDcz7McDxtXX1qf0ToDjwxIvyPnhnPHLRG+kJqLy4FxX4f4gvJQV1hW3OwYgUa3
ylAhPERMXfCReeQxpcwri8QFiW1vuxJIRnTpxIxeU1Ac5Ekce1YqUJHb07dKD6zt
gVHUCsWJnPwcib+a8xjDuTfeMYzYx4FQWYEaYEAZ897ZO1iavnP1wE/dAh8WLDZF
Sz5WqwViuF9O3jZG3Nl6CNZdhVGnkhxq8fgdbdo1cdxaffulxeiEm77lfs7Us166
cZnVuxjPyIH12tpTAlG5ODFI49ru0tAKcihQgdaXggMr5SH00pN3QSVUumy7pLFw
0mnqxO8vwXEwYe2zNMgEn+go0Wn9ksct2wEMIpbRLSHZcMZckX5iwnZuWvT+yY64
KQEiHtTsE2o1Ih9GzpzOpHrkISOBZUtI+VaGAHiwYRKdgaAFTZ9Rk38Sgiv9dk9c
HbggUzNtq7tpJw2rR9q5Kpl01QYpbddykuS1THstYGQNI6rvjx+WVW8ADR4hn/M7
nsNxXAP1Zlj8fltX2csHpt3cF2Dq2rGILfvhyEFR3V2xZocUJFIoxh6IZHtbVPQI
a48VlxsZD4bBTvr5d0eQfv0CAwEAAQ==
-----END RSA PUBLIC KEY-----
```

Le fait d'avoir la clé publique nous permet de vérifier la validité de chaque signature; et comme ça, une signature non valide est trouvée
et qui est supposée signer le message `Pic Sans Nom (3913 m)`. Et voici la signature(faussée) de ce dernier message: 
```
sTL3fvslMBMcSWCELORElJ3Z54cOdM9+PnHg52AdREr9ELNogojXgzVRzRo8kYeM
o/g5GL/0pb3USfWpbbiGIr1aHpwngHGolJ/6rQbT9h2Mgwb2O4UqWET2/MTGK1LF
SNa8X/NbVEiJDFaAhfhtRp0914Ngm76qczGlbQEKI2OhhUU0t4oN6psvIOnuzwzI
Y2fxc/HePQKTsCeyTq6KNaxoIgGIYPkgNtIKWqZEi3Pf4R00IVYcw0H5ohhXQ3x7
zXyla1AizVAGfzYpXcBNNAOrfoLEaSQ+fsxYiWsAwRShZDpctmtPyC+hld1WxZ5l
xH5kk/EyZxMc+tjV6BVixBJmnBe9RDJwYWbAivdZ9r5eu6wQXPlNgj2/bFZkIV1G
K2o5mqwY8her/SZ/Hruwg0pm93MccujCyceM37HbUVuNiDsfDq35A26w+V0h0tyy
B/fdrLQ0/AOO6YEOkXIJ9TR8uTAng5b3b4eE8s2MSnccqRVC3bn+lZD+H5L3Rqpd
559RFRLOOVbh/6SQ9PN4lyYwIu1bkAlq77psl8Ux4e1JpEWC/Gw5xBAuPUesZI8G
Kozbts+Oe9p4ph7i8chytD4faH4rCDcKTaGhfhyOVcsy07KyoGvctrZR1832FLnf
jA966Laow9dU83nzvbuu9B0zVMfavlc3M85oJW7bsKA=
```

Le calcul du RSA utilise le théorème des restes chinois pour alléger le coût en temps, mais ceci
l’expose à de sérieux risques. Dans ce cas, on a une signature faussée exploitable grâce aux
propriétés mathématiques du Théorème des Reste Chinois.

On note `m` la représentation numérique du message "Pic Sans Nom (3913 m)" paddé (1FF...FF00...) avec le format PKCS#1\
`s` la représentation numérique de la signature fausée et `(e:exposant, n:module)` la clé publique.

Les mathématiques du TRC impliquent que pour $u = m – (s)^e mod(n)$, on a que $pgcd(u, n)$ (>1) est un facteur de `n`.

La dernière étape pour trouver un facteur de `n` est de ‘guesser’ de nombre de `FF` dans le padding
de `m`. Un test exhaustif de 0 à 600 est suffisant pour trouver la bonne représentation numérique de `m`.

Une fois qu’on a le premier facteur de `n`, on divise `n` par ce facteur pour trouver le second facteur.
Et puis, on calcule `Phi(n)` (Indicatrice d’Euler), et ensuite on peut retrouver la valeur de la clé
privée qu'on note `d`, en calculant l’inverse multiplicatif de `e modulo Phi(n)`.

Et enfin, l'exploit:

```
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode
from base64 import b64encode
from Crypto.Util.number import bytes_to_long
import math

def modInv(a,p):          # Finds the inverse of a mod p, if it exists
  for i in range(1,p):
    if (i*a)%p==1:
      return i
  return 0



new_pub = '''-----BEGIN RSA PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAyyj+K5YrxLR0K1kurP0K
GtOgXhnBKAkMJgiGu2OrbjRXHy0uATxajodcWbsKSjLuAgsDiO17ADYHBisIfiqo
/eDcz7McDxtXX1qf0ToDjwxIvyPnhnPHLRG+kJqLy4FxX4f4gvJQV1hW3OwYgUa3
ylAhPERMXfCReeQxpcwri8QFiW1vuxJIRnTpxIxeU1Ac5Ekce1YqUJHb07dKD6zt
gVHUCsWJnPwcib+a8xjDuTfeMYzYx4FQWYEaYEAZ897ZO1iavnP1wE/dAh8WLDZF
Sz5WqwViuF9O3jZG3Nl6CNZdhVGnkhxq8fgdbdo1cdxaffulxeiEm77lfs7Us166
cZnVuxjPyIH12tpTAlG5ODFI49ru0tAKcihQgdaXggMr5SH00pN3QSVUumy7pLFw
0mnqxO8vwXEwYe2zNMgEn+go0Wn9ksct2wEMIpbRLSHZcMZckX5iwnZuWvT+yY64
KQEiHtTsE2o1Ih9GzpzOpHrkISOBZUtI+VaGAHiwYRKdgaAFTZ9Rk38Sgiv9dk9c
HbggUzNtq7tpJw2rR9q5Kpl01QYpbddykuS1THstYGQNI6rvjx+WVW8ADR4hn/M7
nsNxXAP1Zlj8fltX2csHpt3cF2Dq2rGILfvhyEFR3V2xZocUJFIoxh6IZHtbVPQI
a48VlxsZD4bBTvr5d0eQfv0CAwEAAQ==
-----END RSA PUBLIC KEY-----'''



k = RSA.importKey(new_pub)

# The ecrypted message
c = "RiK+IgIqPxRSkllkVR2PSJKpEUg95QvaukDIsa64a9Uzyaxw+d2arOIJNLOuZUPSJG3JFJVYjBwR"
c+= "NoISFY+vFfhMt/iMaCVrKewu5G4oco18c5OQDSzsDFkK1376/W8Di0PdmJbaita/mjaMIfEF1iUC"
c+= "+r3n8tBJH2Fz1xAkRTZqZpRh3ImvvOresidMICmVpNc1eQttY956csxMWKWh3UWvP7Czss0f78VL"
c+= "BPZBCA3Vu75KCq8t2H1s1WIa6jqDjI9dX4Pv+K3EqrFexGNHUAvGdrR8f1p2igc5/aatEA3UKYTG"
c+= "jpHnRhF42bHoztMrr3/As7poHVf15wcbirki6YGHxorwreGpy7YvCGLcQS9fGcFlQr6kfFbtPRcH"
c+= "Ci+HcMJV1ZzRSt7onW/yBFnG0uEhAQNhotYYxIT3l7nEZ/jTakS+57dtfPrhZOJSTwh5A8AY5R3X"
c+= "2nN0qUudgf2iFtVznNh0Put8mrn+aFaH3+Egvt/3T2El+sDlfvZdS95zU8sE3cvT2ip0AjoC5kTQ"
c+= "kzXq+ahSKpASuS411OhniNf8hGg5WbSOOg18BrftSBu/uRsoXLPMRATzI6PGwtnQfmE09fE4d1CB"
c+= "ChCbTy4etnVZRuS5HB7qvBKXUTdSZ4FBJxRg3sTQhiuqeV4Bhe5wFYszic/k+QfnMaXcQrPegUk=" 


sig = "sTL3fvslMBMcSWCELORElJ3Z54cOdM9+PnHg52AdREr9ELNogojXgzVRzRo8kYeMo/g5GL/0pb3USfWpbbiGIr1aHpwngHGolJ/6rQbT9h2Mgwb2O4UqWET2/MTGK1LFSNa8X/NbVEiJDFaAhfhtRp0914Ngm76qczGlbQEKI2OhhUU0t4oN6psvIOnuzwzIY2fxc/HePQKTsCeyTq6KNaxoIgGIYPkgNtIKWqZEi3Pf4R00IVYcw0H5ohhXQ3x7zXyla1AizVAGfzYpXcBNNAOrfoLEaSQ+fsxYiWsAwRShZDpctmtPyC+hld1WxZ5lxH5kk/EyZxMc+tjV6BVixBJmnBe9RDJwYWbAivdZ9r5eu6wQXPlNgj2/bFZkIV1GK2o5mqwY8her/SZ/Hruwg0pm93MccujCyceM37HbUVuNiDsfDq35A26w+V0h0tyyB/fdrLQ0/AOO6YEOkXIJ9TR8uTAng5b3b4eE8s2MSnccqRVC3bn+lZD+H5L3Rqpd559RFRLOOVbh/6SQ9PN4lyYwIu1bkAlq77psl8Ux4e1JpEWC/Gw5xBAuPUesZI8GKozbts+Oe9p4ph7i8chytD4faH4rCDcKTaGhfhyOVcsy07KyoGvctrZR1832FLnfjA966Laow9dU83nzvbuu9B0zVMfavlc3M85oJW7bsKA="

m = b'Pic Sans Nom (3913 m)'
m = bytes.hex(m)

pkcsm = ""

P = 0
Q = 0
for i in range(0, 600):
	sig1 = sig
	pkcsm = "1"
	pkcsm += "ff"*i
	pkcsm += "00"
	pkcsm += m
	pkcsm = int(pkcsm, 16)
	sig1 = b64decode(sig1)
	sig1 = bytes_to_long(sig1)
	# ==> gcd((m-(s)^e) mod N, N) = q
	u = k.n
	v = (pkcsm-pow(sig1, k.e, k.n))%u
	q = math.gcd(u, v)
	if (k.n%q == 0) and (q != 1):
		print("OK, q="+str(q)+"\n")
		Q = q
		P = k.n // q

phi = (P-1)*(Q-1)
d = pow(k.e, -1, phi) % phi

c = b64decode(c)
c = bytes_to_long(c)
flag = pow(c, d, k.n)
flag = "1"+hex(flag)[2:]
print(bytes.fromhex(flag).decode("utf-8", 'ignore'))

```

Après l'exécution du script, on obtient:

![screen_flag](../pictures/Screenshot-2024-10-01-223750.png)
