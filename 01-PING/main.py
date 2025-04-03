## On demande à l'utlisation une @ ip a ping
import platform
import subprocess

ip = input("Entrez une adresse ip/url")
#on detecte le sys d'exploitation pour adapter la commande
param = "-n" if platform.system().lower() == "windows" else "-c"

#construire la  commande ping
commande = ["ping" , param, "1",ip]
print("Ping en cours ...")

#On execute la ping
try:
    result = subprocess.run(commande, stdout = subprocess.DEVNULL)
    if result.returncode == 0:
        print("cible en ligne")
    else:
        print("aucune reponse")
except Exception as e:
    print(f"Erreur lors du ping : {e}")
