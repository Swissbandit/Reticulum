Reticulum Netzwerk Stack β <img align="right" src="https://static.pepy.tech/personalized-badge/rns?period=total&units=international_system&left_color=grey&right_color=blue&left_text=Installs"/>
==========

<p align="center"><img width="200" src="https://raw.githubusercontent.com/markqvist/Reticulum/master/docs/source/graphics/rns_logo_512.png"></p>

Reticulum ist der kryptografiebasierte Netzwerkstack für den Aufbau von lokalen und Wide-Area
Netzwerken mit leicht verfügbarer Hardware. Er kann auch bei sehr hohen Latenzzeiten
und extrem geringer Bandbreite arbeiten. Mit Reticulum können Sie Wide-Area-Netzwerke aufbauen
Reticulum ermöglicht den Aufbau von Weitverkehrsnetzen mit handelsüblichen Tools und bietet End-to-End-Verschlüsselung und Konnektivität,
Anonymität des Initiators, autokonfigurierende kryptografisch unterstützter
Multi-Hop-Transport, effiziente Adressierung, fälschungssichere Zustellbestätigungen und mehr.


Die Vision von Reticulum ist es, jedem die Möglichkeit zu geben, sein eigener Netzbetreiber zu sein,
und es billig und einfach zu machen, große Gebiete mit einer Vielzahl unabhängiger, miteinander
verbindbaren und autonomen Netzen abzudecken. Reticulum **ist nicht** nur *ein* Netzwerk.
Es ist **ein Werkzeug** für den Aufbau von *Tausenden von Netzen*. Netzwerke ohne
Kill-Switches, Überwachung, Zensur und Kontrolle. Netzwerke, die frei
interagieren, sich miteinander verbinden und trennen können und keine
zentrale Aufsicht benötigen. Netze für Menschen. *Netzwerke für die Menschen*.


Reticulum ist ein vollständiger Netzwerkstack und stützt sich nicht auf IP oder höhere
Schichten, aber es ist möglich, IP als Träger für Reticulum zu verwenden.
Daher ist es trivial, Reticulum über das Internet oder private IP
Netze zu tunneln.

Da keine Abhängigkeiten von traditionellen Netzwerkstapeln bestehen, entfällt der Overhead,
da für die Implementierung ein direkt auf kryptografische Grundsätze basierender Netzwerkstack erstellt wurde, 
und ermöglicht Ausfallsicherheit und stabile Funktionalität, selbst in offenen
vertrauenslosen Netzwerken.

Es werden keine Kernelmodule oder Treiber benötigt. Reticulum läuft vollständig im
Userland und kann auf praktisch jedem System laufen, auf dem Python 3 läuft.

## Lesen Sie das Handbuch
Die vollständige Dokumentation zu Reticulum finden Sie unter [markqvist.github.io/Reticulum/manual/](https://markqvist.github.io/Reticulum/manual/).

Sie können auch [das Reticulum Handbuch als PDF herunterladen](https://github.com/markqvist/Reticulum/raw/master/docs/Reticulum%20Manual.pdf)

Weitere Informationen finden Sie unter [unsigned.io/projects/reticulum](https://unsigned.io/projects/reticulum/)

## Bemerkenswerte Eigenschaften
- Koordinationslose, weltweit eindeutige Adressierung und Identifizierung
- Vollständig selbstkonfigurierendes Multi-Hop-Routing
- Anonymität des Initiators, Kommunikation ohne Preisgabe der eigenen Identität
- Asymmetrische X25519-Verschlüsselung und Ed25519-Signaturen als Grundlage für die gesamte Kommunikation
- Vorwärtsgeheimnis mit ephemeren Diffie-Hellman-Schlüsseln mit elliptischer Kurve auf Curve25519
- Reticulum verwendet die [Fernet](https://github.com/fernet/spec/blob/master/Spec.md) Spezifikation für On-the-Wire/Over-the-Air-Verschlüsselung
  - Die Schlüssel sind flüchtig und stammen aus einem ECDH-Schlüsselaustausch auf Curve25519
  - AES-128 im CBC-Modus mit PKCS7-Padding
  - HMAC mit SHA256 zur Authentifizierung
  - IVs werden durch os.urandom() erzeugt
- Nicht fälschbare Paketzustellungsbestätigungen
- Eine Vielzahl von unterstützten Schnittstellentypen
- Eine intuitive und leicht zu bedienende API
- Zuverlässige und effiziente Übertragung beliebiger Datenmengen
  - Reticulum kann sowohl wenige Bytes als auch viele Gigabytes an Daten verarbeiten.
  - Sequenzierung, Übertragungskoordination und Prüfsummenbildung erfolgen automatisch
  - Die API ist sehr einfach zu bedienen und liefert den Übertragungsfortschritt
- Leichtgewichtiger, flexibler und erweiterbarer Anfrage/Antwort-Mechanismus
- Effizienter Verbindungsaufbau
  - Die gesamten Bandbreitenkosten für den Aufbau einer verschlüsselten Verbindung betragen 3 Pakete mit insgesamt 297 Byte
  - Geringe Kosten für das Offenhalten von Verbindungen mit nur 0,44 Bit pro Sekunde

## Beispiele für Reticulum-Anwendungen
Wenn Sie sich schnell einen Überblick über die Möglichkeiten von Reticulum verschaffen möchten, werfen Sie einen Blick auf die
folgenden Ressourcen.

- Eine netzunabhängige, verschlüsselte und widerstandsfähige Mesh-Kommunikationsplattform finden Sie unter [Nomad Network](https://github.com/markqvist/NomadNet)
- Die Android-, Linux- und macOS-Anwendung [Sideband](https://github.com/markqvist/Sideband) verfügt über eine grafische Oberfläche und legt den Schwerpunkt auf Benutzerfreundlichkeit.
- [LXMF](https://github.com/markqvist/lxmf) ist ein verteiltes, verzögerungs- und unterbrechungstolerantes Nachrichtenübertragungsprotokoll, das auf Reticulum aufbaut.

## Wo kann Reticulum eingesetzt werden?
Über praktisch jedes Medium, das mindestens einen Halbduplex-Kanal unterstützen kann
mit einem Durchsatz von 500 Bit pro Sekunde und einer MTU von 500 Byte. Datenfunkgeräte,
Modems, LoRa-Funkgeräte, serielle Leitungen, AX.25 TNCs, digitale Amateurfunkmodi,
WiFi- und Ethernet-Geräte, optische Verbindungen im freien Raum und ähnliche Systeme sind alles Beispiele für physikalische Geräte, die Reticulum verwenden kann.

Eine Open-Source-Schnittstelle auf LoRa-Basis namens
[RNode](https://markqvist.github.io/Reticulum/manual/hardware.html#rnode) 
wurde speziell für die Verwendung mit Reticulum entwickelt. Man kann es selbst bauen oder als komplettes Gerät kaufen, das nur noch einen
USB-Anschluss an den Host benötigt.

Reticulum kann auch über bestehende IP-Netzwerke gekapselt werden, so dass dem Einsatz über kabelgebundenes Ethernet, 
Ihr lokales WiFi-Netzwerk oder das Internet nichts im Wege steht, wo es genauso gut funktioniert. 
Eine der Stärken von Reticulum besteht darin, dass Sie verschiedene Medien ganz einfach zu einem selbstkonfigurierenden, 
belastbaren und verschlüsselten Mesh verbinden können, wobei jede verfügbare Infrastruktur genutzt werden kann.

So ist es zum Beispiel möglich, einen Raspberry Pi sowohl mit einem LoRa
Funkgerät, einem Packet-Radio-TNC und einem WiFi-Netzwerk zu verbinden. Sobald die Schnittstellen
konfiguriert sind, kümmert sich Reticulum um den Rest, und jedes Gerät im WiFi
Netzwerk des Gateway Knotens kann mit der LoRa- und Paketfunkseite des Netzwerks kommunizieren und umgekehrt.

## Wie fange ich an?
Wie Sie am besten mit dem Reticulum Network Stack beginnen, hängt davon ab, was Sie tun möchten. Ausführliche Details und Beispiele finden Sie im Abschnitt 
[Schnelleinstieg](https://markqvist.github.io/Reticulum/manual/gettingstartedfast.html) 
im [Reticulum Manual](https://markqvist.github.io/Reticulum/manual/).

Der einfachste Weg, Reticulum und die zugehörigen Dienstprogramme auf Ihrem System zu installieren, führt über pip:

```bash
pip install rns
```

Sie können dann jedes Programm starten, das Reticulum verwendet, oder Reticulum als
Systemdienst starten mit [dem Dienstprogramm rnsd](https://markqvist.github.io/Reticulum/manual/using.html#the-rnsd-utility).

Beim ersten Start erstellt Reticulum eine Standardkonfigurationsdatei,
die eine grundlegende Verbindung zu anderen Reticulum-Peers herstellt, die möglicherweise lokal
erreichbar sind. Die Standardkonfigurationsdatei enthält einige Beispiele und Verweise für die
Erstellung einer komplexeren Konfiguration.

Wenn Sie eine alte Version von `pip` auf Ihrem System haben, müssen Sie sie möglicherweise zuerst mit `pip install pip --upgrade` aktualisieren. 
Wenn Sie `pip` noch nicht installiert haben, können Sie es mit dem Paketmanager Ihres Systems mit `sudo apt install python3-pip` oder ähnlichem installieren.

Ausführlichere Beispiele für die Erweiterung der Kommunikation über viele Medien wie 
wie Packet Radio oder LoRa, serielle Schnittstellen oder über schnelle IP-Verbindungen und das Internet unter Verwendung der 
UDP- und TCP-Schnittstellen werfen Sie einen Blick auf die [Unterstützte Schnittstellen](https://markqvist.github.io/Reticulum/manual/interfaces.html) 
Abschnitt des [Reticulum Handbuchs](https://markqvist.github.io/Reticulum/manual/).

## Enthaltene Dienstprogramme
Reticulum enthält eine Reihe nützlicher Hilfsprogramme für die Verwaltung Ihrer Netzwerke, 
Anzeigen von Status und Informationen sowie für andere Aufgaben. Mehr über diese Programme erfahren Sie 
unter [Enthaltene Hilfsprogramme].(https://markqvist.github.io/Reticulum/manual/using.html#included-utility-programs) 
im Abschnitt des [Reticulum Handbuchs](https://markqvist.github.io/Reticulum/manual/).

- Der System-Daemon `rnsd` für den Betrieb von Reticulum als immer verfügbarer Dienst
- Ein Dienstprogramm für den Schnittstellenstatus namens "rnstatus", das Informationen über Schnittstellen anzeigt
- Das Tool `rnpath` zum Nachschlagen und Verwalten von Pfaden, mit dem Sie Pfad-Tabellen anzeigen und ändern können
- Ein Diagnosewerkzeug namens `rnprobe` zur Überprüfung der Konnektivität zu Zielen
- Ein einfaches Dateiübertragungsprogramm namens `rncp`, das das Kopieren von Dateien auf entfernte Systeme erleichtert
- Mit dem Programm `rnx` zur Ausführung entfernter Befehle können Sie Befehle und
  Programme ausführen und Ausgaben von entfernten Systemen abrufen

Alle Tools, einschließlich `rnx` und `rncp`, arbeiten zuverlässig und gut auch über sehr
Verbindungen mit geringer Bandbreite wie LoRa oder Packet Radio.

## Unterstützte Schnittstellentypen und Geräte

Reticulum implementiert eine Reihe allgemeiner Schnittstellentypen, die die meisten der
Kommunikationshardware abdeckt, mit der Reticulum betrieben werden kann. Wenn Ihre Hardware
nicht unterstützt wird, ist es relativ einfach, eine Schnittstellenklasse zu implementieren.
Ich bin dankbar für Pull-Requests für benutzerdefinierte Schnittstellen, wenn sie allgemein nützlich sind.

Derzeit werden die folgenden Schnittstellen unterstützt:

- Jedes Ethernet-Gerät
- LoRa unter Verwendung von [RNode](https://unsigned.io/projects/rnode/)
- Packet Radio TNCs (mit oder ohne AX.25)
- KISS-kompatible Hardware- und Software-Modems
- Jedes Gerät mit einer seriellen Schnittstelle
- TCP über IP netzwerke
- UDP über IP netzwerke
- Externe Programme über stdio oder Pipes
- Spezifische Hardware über stdio oder Pipes

## Leistung
Reticulum zielt auf einen *sehr* großen nutzbaren Leistungsbereich ab, legt aber den Schwerpunkt auf
Funktionalität und Leistung auf Medien mit geringer Bandbreite. Das Ziel ist es
einen dynamischen Leistungsbereich von 250 Bit pro Sekunde bis zu 1 Gigabit
pro Sekunde auf normaler Hardware zu ermöglichen.

Derzeit liegt der nutzbare Leistungsbereich bei etwa 500 Bit pro Sekunde
bis 20 Megabit pro Sekunde, wobei schnellere physikalische Medien nicht
gesättigt sind. Eine über das derzeitige Niveau hinausgehende Leistung ist für künftige
Upgrades vorgesehen, hat aber zum jetzigen Zeitpunkt keine hohe Priorität.

## Aktueller Stand
Reticulum sollte derzeit als Beta-Software betrachtet werden. Alle Kernprotokoll
Funktionen sind implementiert und funktionieren, aber es werden noch im realen Einsatz erforscht werden. 
Es wird Bugs geben. Die API und das Leitungsformat können derzeit als relativ stabil angesehen werden, 
können sich aber ändern, wenn dies gerechtfertigt ist.

## Entwicklungsfahrplan
- Verbesserung [des Handbuchs](https://markqvist.github.io/Reticulum/manual/) mit Abschnitten speziell für Anfänger
- Leistungs- und Speicheroptimierung
- Dienstprogramme für die Verwaltung von Identitäten, Signierung und Verschlüsselung
- Benutzerfreundliches Interface-Konfigurationswerkzeug
- Mehr Schnittstellentypen für noch breitere Kompatibilität
  - Normale ESP32-Geräte (ESP-Now, WiFi, Bluetooth, etc.)
  - Weitere LoRa-Transceivers
  - IR Transceivers
- OpenWRT support
- Metrikbasierte Pfadauswahl
- Verteiltes Zielnamensystem
- Netzwerkweiter Pfadausgleich
- Global routbarer Multicast
- Bindungen für andere Programmiersprachen
- Mehrere Pfade in der Pfad-Tabelle für schnelle Wiederherstellung bei Verbindungsausfällen
- Eine portable Reticulum-Implementierung in C, siehe [#21](https://github.com/markqvist/Reticulum/discussions/21)
- Einfache Möglichkeit zur gemeinsamen Nutzung von Schnittstellenkonfigurationen, siehe [#19](https://github.com/markqvist/Reticulum/discussions/19)
- Weitere Schnittstellentypen
  - AT-kompatible Modems
  - Optische Medien
  - AWDL / OWL
  - HF Modems
  - CAN-bus
  - ZeroMQ
  - MQTT
  - XBee
  - SPI
  - i²c
  - Tor

## Abhängigkeiten
Die Installation des Standardpakets `rns` erfordert die unten aufgeführten Abhängigkeiten.
Fast alle Systeme und Distributionen haben leicht verfügbare Pakete für diese Abhängigkeiten, 
und wenn das `rns`-Paket mit `pip` installiert wird,
werden diese ebenfalls heruntergeladen und installiert.

- [PyCA/cryptography](https://github.com/pyca/cryptography)
- [netifaces](https://github.com/al45tair/netifaces)
- [pyserial](https://github.com/pyserial/pyserial)

Auf ungewöhnlicheren Systemen und in einigen seltenen Fällen ist es möglicherweise nicht möglich
ein oder mehrere der oben genannten Module zu installieren oder gar zu kompilieren. In solchen Situationen,
können Sie stattdessen das Paket `rnspure` verwenden, das keine externen Abhängigkeiten für die Installation besitzt. 
Bitte beachten Sie, dass der Inhalt der Pakete `rns` und `rnspure` Pakete *identisch* sind. 
Der einzige Unterschied ist, dass das `rnspure` Paket keine Abhängigkeiten auflistet, die für die Installation erforderlich sind.

Unabhängig davon, wie Reticulum installiert und gestartet wird, lädt es externe
Abhängigkeiten nur, wenn sie *benötigt* und *verfügbar* sind. Wenn Sie zum Beispiel
Reticulum auf einem System verwenden möchten, das folgende Komponenten nicht unterstützt
[pyserial](https://github.com/pyserial/pyserial), ist es durchaus möglich
mit dem Paket `rnspure` zu installieren, aber Reticulum kann dann keine
serielle Schnittstellen verwenden. Alle anderen verfügbaren Module werden weiterhin geladen, welche
benötigt werden.

**Bitte beachten Sie!** Wenn Sie das Paket `rnspure` verwenden, um Reticulum auf Systemen zu betreiben
die keine Unterstützung für [PyCA/cryptography](https://github.com/pyca/cryptography)
bieten, ist es wichtig, dass Sie die folgenden Informationen lesen und verstehen im [Kryptographische Primitive](#cryptographic-primitives) Abschnitt dieses Dokuments.

## Öffentliches Testnetz
Wenn Sie einfach nur experimentieren wollen, ohne ein physisches Netzwerk aufzubauen, 
sind Sie herzlich eingeladen, dem Unsigned.io RNS Testnet beizutreten. 
Das Testnet ist genau das, ein informelles Netzwerk zum Testen und Experimentieren. 
Es wird die meiste Zeit verfügbar sein und jeder kann beitreten, aber das bedeutet auch, 
dass es keine Garantien für die Verfügbarkeit der Dienste gibt.

Im Testnetz läuft die allerneueste Version von Reticulum (oft sogar kurz bevor sie öffentlich freigegeben wird). 
Manchmal werden experimentelle Versionen von Reticulum auf den Knoten des Testnetzes eingesetzt werden, 
was dazu führen kann, dass seltsames Verhalten auftreten kann. 
Wenn Sie das alles nicht abschreckt, können Sie sich dem Testnetz entweder über TCP oder I2P anschliessen. 
Fügen Sie einfach eine der folgenden Schnittstellen zu Ihrer Reticulum-Konfigurationsdatei hinzu:

```
# TCP/IP Schnittstelle zum Dublin Hub
  [[RNS Testnet Dublin]]
    type = TCPClientInterface
    enabled = yes
    target_host = dublin.connect.reticulum.network
    target_port = 4965

# TCP/IP Schnittstelle zum Frankfurt Hub
  [[RNS Testnet Frankfurt]]
    type = TCPClientInterface
    enabled = yes
    target_host = frankfurt.connect.reticulum.network
    target_port = 5377

# Schnittstelle zum I2P Hub A
  [[RNS Testnet I2P Hub A]]
    type = I2PInterface
    enabled = yes
    peers = pmlm3l5rpympihoy2o5ago43kluei2jjjzsalcuiuylbve3mwi2a.b32.i2p

# Schnittstelle zum I2P Hub B
  [[RNS Testnet I2P Hub B]]
    type = I2PInterface
    enabled = yes
    peers = iwoqtz22dsr73aemwpw7guocplsjjoamyl7sogj33qtcd6ds4mza.b32.i2p
```

Das Testnetz enthält auch eine Reihe von [Nomad Network](https://github.com/markqvist/nomadnet) Knoten, und LXMF-Propagationsknoten,
sowie Peers von der [Sideband App](https://github.com/markqvist/Sideband)

## Reticulum Entwicklung unterstützen
Sie können die weitere Entwicklung offener, freier und privater Kommunikationssysteme unterstützen, indem Sie über einen der folgenden Kanäle spenden:

- Monero:
 ```
  84FpY1QbxHcgdseePYNmhTHcrgMX4nFfBYtz2GKYToqHVVhJp8Eaw1Z1EedRnKD19b3B8NiLCGVxzKV17UMmmeEsCrPyA5w
  ```
- Ethereum
  ```
  0x81F7B979fEa6134bA9FD5c701b3501A2e61E897a
  ```
- Bitcoin
  ```
  3CPmacGm34qYvR6XWLVEJmi2aNe3PZqUuq
  ```
- Ko-Fi: https://ko-fi.com/markqvist

Sind bestimmte Funktionen in der Entwicklungs-Roadmap für Sie oder Ihr Unternehmen wichtig?
Organisation? Machen Sie sie schnell zur Realität, indem Sie ihre Umsetzung sponsern.

## Kryptographische Primitive
Reticulum verwendet eine einfache Reihe effizienter, starker und moderner kryptographischer Primitiven, 
mit weithin verfügbaren Implementierungen, die sowohl auf Allzweck-CPUs und Mikrocontrollern verwendet werden können. 
Die notwendigen Primitive sind:

- Ed25519 für Unterschriften
- X22519 für den Austausch von ECDH-Schlüsseln
- HKDF für die Schlüsselableitung
- Modifiziertes Fernet für verschlüsselte Token
  - AES-128 in CBC modus
  - HMAC für die Authentifizierung von Nachrichten
  - Keine Felder Fernet-Version und Zeitstempel
- SHA-256
- SHA-512

In der Standard-Installationskonfiguration werden die Primitive `X25519`, `Ed25519` und
AES-128-CBC"-Primitive werden von [OpenSSL](https://www.openssl.org/)
(via des [PyCA/cryptography](https://github.com/pyca/cryptography) Packets).
Die Hashing-Funktionen `SHA-256` und `SHA-512` werden von der Standard
Python [hashlib](https://docs.python.org/3/library/hashlib.html) geliefert. 
Die `HKDF`, `HMAC`, `Fernet` Primitive und die Paddingfunktion `PKCS7` werden immer
von den folgenden internen Implementierungen bereitgestellt:

- [HKDF.py](RNS/Cryptography/HKDF.py)
- [HMAC.py](RNS/Cryptography/HMAC.py)
- [Fernet.py](RNS/Cryptography/Fernet.py)
- [PKCS7.py](RNS/Cryptography/PKCS7.py)


Reticulum enthält auch eine vollständige Implementierung aller notwendigen Primitive in reinem Python. 
Sind OpenSSL und PyCA beim Start von Reticulum nicht auf dem System verfügbar, 
verwendet Reticulum stattdessen die internen reinen Python Primitive. 
Eine triviale Folge hiervon ist die Leistung, da das OpenSSL Backend *viel* schneller ist. 
Die wichtigste Konsequenz ist jedoch die potenzielle Einbuße an Sicherheit durch die Verwendung von Primitiven, 
die nicht in gleichem Maße geprüft und getestet wurden wie die von OpenSSL.

Wenn Sie die internen reinen Python-Primitive verwenden wollen, ist es **empfehlenswert**, 
dass Sie sich über die damit verbundenen Risiken im Klaren sind, 
um eine fundierte Entscheidung darüber zu treffen, ob diese Risiken für Sie akzeptabel sind.

Reticulum ist eine relativ junge Software und sollte auch als solche betrachtet werden. 
Es wurde zwar unter Berücksichtigung der besten Kryptographie-Praktiken entwickelt, 
aber es wurde noch nicht extern auf seine Sicherheit hin überprüft, 
und es könnten sehr wohl noch Datenschutz- oder Sicherheitslücken enthalten. 
Wenn Sie mithelfen oder ein Audit sponsern wollen, nehmen Sie bitte Kontakt auf.

## Danksagungen & Credits
Reticulum kann nur existieren, weil es auf einem Berg von Open-Source-Arbeit aufbaut, 
den Beiträgen aller Beteiligten, die das Projekt über die Jahre hinweg unterstützt haben. 
An alle, die geholfen haben, vielen Dank.

Eine Reihe anderer Module und Projekte sind entweder ein Teil davon oder werden von Reticulum verwendet. 
Ein herzliches Dankeschön an die Autoren und Mitwirkenden der folgenden Projekte:

- [PyCA/cryptography](https://github.com/pyca/cryptography), *BSD License*
- [Pure-25519](https://github.com/warner/python-pure25519) by [Brian Warner](https://github.com/warner), *MIT License*
- [Pysha2](https://github.com/thomdixon/pysha2) by [Thom Dixon](https://github.com/thomdixon), *MIT License*
- [Python-AES](https://github.com/orgurar/python-aes) by [Or Gur Arie](https://github.com/orgurar), *MIT License*
- [Curve25519.py](https://gist.github.com/nickovs/cc3c22d15f239a2640c185035c06f8a3#file-curve25519-py) by [Nicko van Someren](https://gist.github.com/nickovs), *Public Domain*
- [I2Plib](https://github.com/l-n-s/i2plib) by [Viktor Villainov](https://github.com/l-n-s)
- [PySerial](https://github.com/pyserial/pyserial) by Chris Liechti, *BSD License*
- [Netifaces](https://github.com/al45tair/netifaces) by [Alastair Houghton](https://github.com/al45tair), *MIT License*
- [Configobj](https://github.com/DiffSK/configobj) by Michael Foord, Nicola Larosa, Rob Dennis & Eli Courtwright, *BSD License*
- [Six](https://github.com/benjaminp/six) by [Benjamin Peterson](https://github.com/benjaminp), *MIT License*
- [Umsgpack.py](https://github.com/vsergeev/u-msgpack-python) by [Ivan A. Sergeev](https://github.com/vsergeev)
- [Python](https://www.python.org)
