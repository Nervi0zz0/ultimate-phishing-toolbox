
<p align="center">
  <img src="assets/nervi0zz0.png" alt="Nerviozzo Blue Team Cybersecurity Logo" width="350"/>
</p>

---
# 🎣🛡️ Phishing Analysis Hub 🛡️🎣



[![Awesome](https://awesome.re/badge.svg)](https://awesome.re) [![GitHub contributors](https://img.shields.io/github/contributors/Nervi0zz0/ultimate-phishing-toolbox)](https://github.com/Nervi0zz0/ultimate-phishing-toolbox/graphs/contributors) [![GitHub last commit](https://img.shields.io/github/last-commit/Nervi0zz0/ultimate-phishing-toolbox)](https://github.com/Nervi0zz0/ultimate-phishing-toolbox/commits/main) [![GitHub stars](https://img.shields.io/github/stars/Nervi0zz0/ultimate-phishing-toolbox?style=social)](https://github.com/Nervi0zz0/ultimate-phishing-toolbox/stargazers)

**Bienvenido a la colección definitiva de herramientas, plataformas y recursos para detectar, analizar y combatir el phishing en todas sus formas.**

El phishing sigue siendo una de las amenazas cibernéticas más persistentes y dañinas. Este repositorio tiene como objetivo ser una **guía viva y colaborativa** para profesionales de ciberseguridad, analistas SOC, investigadores, estudiantes y cualquier persona interesada en comprender y neutralizar estas amenazas.

> **Nota:** Algunas herramientas, especialmente las de frameworks de ataque, deben usarse **exclusivamente** en entornos controlados, con autorización explícita y con fines éticos (pentesting, formación, investigación). El uso indebido es ilegal y no ético.

---

## 📖 Glosario Rápido

Para entender mejor las descripciones:

* **IOC:** Indicator of Compromise (Indicador de Compromiso - ej. URL, hash de archivo, IP).
* **Sandbox:** Entorno aislado para ejecutar software sospechoso de forma segura.
* **MITM:** Man-in-the-Middle (Ataque de intermediario).
* **OSINT:** Open Source Intelligence (Inteligencia de Fuentes Abiertas).
* **FOSS:** Free and Open Source Software (Software Libre y de Código Abierto).
* **API:** Application Programming Interface (Interfaz para que programas interactúen).
* **Gateway:** Punto de control que filtra el tráfico (en este caso, email).

---

## 🗺️ Índice Detallado

* [I. 🧠 Inteligencia de Amenazas y Fuentes de Datos](#i--inteligencia-de-amenazas-y-fuentes-de-datos)
    * [Feeds y Bases de Datos de Phishing](#feeds-y-bases-de-datos-de-phishing)
    * [Reputación de IP/Dominios](#reputación-de-ipdominios)
* [II. 🔬 Herramientas de Análisis Directo](#ii--herramientas-de-análisis-directo)
    * [Escáneres Online de URL/Archivos](#escáneres-online-de-urlarchivos)
    * [Análisis de Email (Cabeceras, Contenido, Adjuntos)](#análisis-de-email-cabeceras-contenido-adjuntos)
    * [Entornos Sandbox (Online y Auto-alojados)](#entornos-sandbox-online-y-auto-alojados)
* [III. 🛡️ Sistemas de Prevención y Detección](#iii--sistemas-de-prevención-y-detección)
    * [Gateways y Servicios de Seguridad de Email (Enfoque Comercial)](#gateways-y-servicios-de-seguridad-de-email-enfoque-comercial)
    * [Protección Integrada en Navegador](#protección-integrada-en-navegador)
* [IV. 🎓 Simulación, Formación y Seguridad Ofensiva](#iv--simulación-formación-y-seguridad-ofensiva)
    * [Plataformas de Simulación y Concienciación](#plataformas-de-simulación-y-concienciación)
    * [Frameworks para Campañas de Phishing Ético](#frameworks-para-campañas-de-phishing-ético-¡usar-con-responsabilidad)
* [V. 🛠️ Herramientas y Frameworks de Apoyo](#v--herramientas-y-frameworks-de-apoyo)
    * [Herramientas OSINT para Contexto de Phishing](#herramientas-osint-para-contexto-de-phishing)
    * [Frameworks Generales de Seguridad](#frameworks-generales-de-seguridad)
* [VI. 📚 Aprendizaje y Recursos Adicionales](#vi--aprendizaje-y-recursos-adicionales)
    * [Ejemplos de Flujos de Trabajo (Ideas)](#ejemplos-de-flujos-de-trabajo-ideas)
    * [Lecturas Recomendadas y Artículos](#lecturas-recomendadas-y-artículos)
    * [Listas "Awesome" Relacionadas](#listas-awesome-relacionadas)
* [VII. 🤝 Comunidad](#vii--comunidad)
    * [Guía de Contribución](#guía-de-contribución)
    * [Código de Conducta](#código-de-conducta)
    * [Licencia](#licencia)

---

## I. 🧠 Inteligencia de Amenazas y Fuentes de Datos

Fuentes esenciales para obtener información actualizada sobre amenazas activas.

### Feeds y Bases de Datos de Phishing

| Icon | Herramienta      | Descripción Clave                                                     | Modelo      | Link                                        |
| :--: | :--------------- | :-------------------------------------------------------------------- | :---------- | :------------------------------------------ |
| 🎣 | **PhishTank** | Base de datos colaborativa de sitios de phishing verificados.       | Gratuito/API| [phishtank.com](https://www.phishtank.com/)   |
| 🐟 | **OpenPhish** | Feed de URLs de phishing en tiempo real. Alta calidad (Comercial).    | Comercial/API| [openphish.com](https://openphish.com/)     |
| 🤖 | **CheckPhish** | Detección de phishing basada en IA, ofrece API.                     | Freemium/API| [checkphish.ai](https://checkphish.ai/)   |
|  MISP | **MISP Project** | Plataforma FOSS para correlacionar y compartir IOCs (incl. phishing). | FOSS        | [misp-project.org](https://www.misp-project.org/) |
| 📊 | **PhishStats** | Estadísticas y datos sobre campañas de phishing.                      | Gratuito/API| [phishstats.info](https://phishstats.info/) |

### Reputación de IP/Dominios

| Icon | Herramienta      | Descripción Clave                                                    | Modelo      | Link                                                          |
| :--: | :--------------- | :------------------------------------------------------------------- | :---------- | :------------------------------------------------------------ |
| 🤬 | **AbuseIPDB** | Base de datos colaborativa de IPs asociadas a actividad maliciosa.     | Freemium/API| [abuseipdb.com](https://www.abuseipdb.com/)                   |
| 🔍 | **VirusTotal** | Analiza IPs y Dominios contra múltiples motores y datasets.            | Freemium/API| [virustotal.com](https://www.virustotal.com/)                 |
| 🛡️ | **Talos Reputation** | Centro de reputación de IP/Dominios de Cisco Talos.                | Gratuito    | [talosintelligence.com/reputation_center](https://talosintelligence.com/reputation_center) |
| 🌐 | **URLVoid** | Escanea URLs y Dominios con múltiples servicios de reputación.         | Freemium/API| [urlvoid.com](https://www.urlvoid.com/)                       |
| 🌀 | **ThreatConnect**| Plataforma de Threat Intelligence (incluye reputación).              | Comercial   | [threatconnect.com](https://threatconnect.com/)               |
| 💡 | **IBM X-Force** | Portal de inteligencia de amenazas con reputación de IP/URL/Vulnerabilidades. | Freemium/API| [exchange.xforce.ibmcloud.com](https://exchange.xforce.ibmcloud.com/) |

---

## II. 🔬 Herramientas de Análisis Directo

Herramientas prácticas para diseccionar artefactos de phishing.

### Escáneres Online de URL/Archivos

| Icon | Herramienta        | Descripción Clave                                                              | Modelo      | Link                                            |
| :--: | :----------------- | :----------------------------------------------------------------------------- | :---------- | :---------------------------------------------- |
| 🌍 | **VirusTotal** | Estándar de facto para analizar URLs y archivos con múltiples motores AV.        | Freemium/API| [virustotal.com](https://www.virustotal.com/)   |
| 🔗 | **URLScan.io** | Escanea URLs y proporciona información detallada sobre la página y recursos.   | Freemium/API| [urlscan.io](https://urlscan.io/)               |
| 💨 | **Any.Run** | Sandbox interactivo online, excelente para análisis rápido de URLs/Archivos. | Freemium    | [any.run](https://any.run/)                     |
| ✅ | **CheckPhish** | Escáner rápido basado en IA específico para detectar phishing.                 | Freemium/API| [checkphish.ai](https://checkphish.ai/)       |
| 📄 | **Hybrid Analysis**| Servicio gratuito de análisis de malware (sandbox + estático).               | Gratuito    | [hybrid-analysis.com](https://www.hybrid-analysis.com/) |
| ❓ | **IsItPhishing** | Plataforma de detección de phishing (puede requerir buscar URL actualizada).   | Variable    | (Buscar enlace)                                 |
| 🔒 | **ScanURL** | Servicio web independiente para escanear URLs.                                 | Gratuito    | [scanurl.net](https://scanurl.net/)             |

### Análisis de Email (Cabeceras, Contenido, Adjuntos)

| Icon | Herramienta         | Descripción Clave                                                            | Modelo      | Link                                                                 |
| :--: | :------------------ | :--------------------------------------------------------------------------- | :---------- | :------------------------------------------------------------------- |
| 🧐 | **MxToolbox Headers**| Analizador online fácil de usar para cabeceras de email.                   | Gratuito    | [mxtoolbox.com/EmailHeaders.aspx](https://mxtoolbox.com/EmailHeaders.aspx) |
| 🇬 | **Google Messageheader**| Analizador de cabeceras oficial de Google (parte de G Suite Toolbox).      | Gratuito    | [toolbox.googleapps.com/apps/messageheader/](https://toolbox.googleapps.com/apps/messageheader/) |
| 🔧 | **PhishTool** | Software/Servicio para análisis integrado de emails, extracción de IOCs.   | Comercial   | [phishtool.com](https://phishtool.com/)                              |
| 🤖 | **ThePhish** | Framework FOSS automatizado para analizar EMLs (usa TheHive/Cortex/MISP). | FOSS        | [GitHub](https://github.com/emalderson/ThePhish)                     |
| 📎 | **Outlook/Thunderbird Add-ons** | Extensiones como "ImportExportTools NG" (TB) para manejar EMLs/MSGs.   | FOSS/Gratuito | (Buscar en tiendas de complementos)                                  |
| ✓ | **Email Veritas** | Servicios para verificar remitentes y analizar emails.                      | Comercial   | (Buscar enlace)                                                      |

### Entornos Sandbox (Online y Auto-alojados)

| Icon | Herramienta        | Descripción Clave                                                               | Modelo            | Link                                              |
| :--: | :----------------- | :------------------------------------------------------------------------------ | :---------------- | :------------------------------------------------ |
| ☁️ | **Any.Run** | Sandbox interactivo online, ideal para análisis rápidos y visuales.           | Freemium          | [any.run](https://any.run/)                       |
| 🐧 | **Cuckoo Sandbox** | El estándar FOSS para análisis automatizado de malware (auto-alojado).      | FOSS              | [cuckoosandbox.org](https://cuckoosandbox.org/)     |
| ☁️ | **Hybrid Analysis** | Sandbox online gratuito de CrowdStrike.                                       | Gratuito          | [hybrid-analysis.com](https://www.hybrid-analysis.com/) |
| ☁️ | **Joe Sandbox Cloud**| Sandbox comercial avanzado con análisis muy detallados.                      | Comercial         | [joesandbox.com](https://www.joesandbox.com/)     |
| 📦 | **Triage** | Plataforma de análisis de malware y sandbox (orientada a equipos).            | Comercial         | [tria.ge](https://tria.ge/)                       |
| 🐳 | **Docker Sandboxes** | Contenedores Docker preconfigurados con herramientas de análisis (buscar en Docker Hub). | FOSS/Variable     | (Buscar en Docker Hub, ej. `remnux/`)           |

---

## III. 🛡️ Sistemas de Prevención y Detección

Soluciones a nivel de sistema o red para bloquear el phishing antes de que llegue al usuario.

### Gateways y Servicios de Seguridad de Email (Enfoque Comercial)

> Estas son soluciones empresariales robustas, generalmente de pago.

* **Proofpoint Email Protection:** Líder del mercado en protección avanzada contra amenazas por email.
* **Mimecast Email Security:** Seguridad Cloud con sandboxing, protección de URLs/adjuntos y DMARC.
* **Barracuda Email Protection:** Suite completa (gateway, DMARC, respuesta a incidentes, formación).
* **Microsoft Defender for Office 365:** Protección integrada en el ecosistema M365 (ATP).
* **Google Workspace Security:** Protección integrada en Gmail/Workspace (incl. sandbox).
* **Fortinet FortiMail:** Secure Email Gateway físico o virtual.
* **Cofense:** Plataforma centrada en detección y respuesta a phishing reportado por usuarios.
* **Avanan (Check Point):** Seguridad de email cloud-native vía API, buena para Office 365/Gmail.
* **PhishTitan (TitanHQ):** Defensa anti-phishing basada en IA, integrada con SpamTitan.
* **OPSWAT Email Security:** Enfocado en desarmado y reconstrucción de contenido (CDR).

### Protección Integrada en Navegador

| Icon | Herramienta             | Descripción Clave                                                           | Modelo     | Notas                                               |
| :--: | :---------------------- | :-------------------------------------------------------------------------- | :--------- | :-------------------------------------------------- |
| 엣지 | **Microsoft SmartScreen** | Integrado en Edge y Windows, bloquea sitios/descargas maliciosos.             | Integrado  | Parte del sistema operativo y navegador Edge.      |
| 🌐 | **Google Safe Browse** | Tecnología base en Chrome, Firefox, Safari para advertir de sitios peligrosos. | Integrado  | API disponible para desarrolladores.               |
| 🛡️ | **Extensiones de Seguridad** | Antivirus (Avast, Bitdefender), Adblockers (uBlock Origin), Privacidad (Privacy Badger) y específicas (Netcraft) pueden bloquear URLs maliciosas. | Variable   | Revisar permisos y fiabilidad de las extensiones. |

---

## IV. 🎓 Simulación, Formación y Seguridad Ofensiva

Herramientas para evaluar la preparación humana y realizar pruebas de penetración éticas.

### Plataformas de Simulación y Concienciación

> Soluciones (mayormente comerciales) para entrenar a usuarios.

* **KnowBe4:** Líder en formación de concienciación y simulación de phishing.
* **Cofense PhishMe:** Plataforma de simulación y reporting integrado.
* **Proofpoint Security Awareness Training:** Módulos de formación y simulación.
* **Sophos Phish Threat:** Simulación integrada con la suite de Sophos.
* **Microsoft Attack Simulation Training:** Dentro de Microsoft 365 Defender.
* **Guardey:** Plataforma gamificada de formación en ciberseguridad.
* **Hoxhunt:** Formación personalizada y automatizada.
* **Infosec IQ / Skills:** Formación y simulación (parte de Cengage).
* **SafeTitan (TitanHQ):** Formación en tiempo real integrada con protección.
* **GoPhish:** Framework FOSS que puede usarse para formación interna (requiere configuración manual).

### Frameworks para Campañas de Phishing Ético (¡Usar con responsabilidad!)

> **⚠️ Advertencia:** Estas herramientas son poderosas. Su uso debe ser **legal, ético y autorizado**.

| Icon | Herramienta                  | Descripción Clave                                                               | Modelo      | Link                                                                  |
| :--: | :--------------------------- | :------------------------------------------------------------------------------ | :---------- | :-------------------------------------------------------------------- |
| 🎣 | **Gophish** | El estándar FOSS para crear y gestionar campañas de phishing simuladas.         | FOSS        | [getgophish.com](https://getgophish.com/)                             |
| 🔧 | **SET (Social-Engineer Toolkit)** | Framework Python clásico para múltiples ataques de ingeniería social.       | FOSS        | [GitHub](https://github.com/trustedsec/social-engineer-toolkit)       |
| 😈 | **Evilginx2 / 3** | Framework MITM avanzado para robar credenciales y tokens de sesión (bypass 2FA). | FOSS        | [GitHub (kgretzky)](https://github.com/kgretzky/evilginx2)            |
| 👑 | **King Phisher** | Framework FOSS para campañas a gran escala, con buena gestión de servidor.     | FOSS        | [GitHub (rsmusllp)](https://github.com/rsmusllp/king-phisher)         |
| 🐠 | **SocialFish / HiddenEye / etc.** | Varias herramientas FOSS (a menudo forks) con plantillas web y funciones MITM. | FOSS        | (Buscar activamente en GitHub, la popularidad y mantenimiento varían) |
| 🔥 | **CredSniper** | Herramienta específica para crear páginas de login falsas y capturar credenciales. | FOSS        | [GitHub](https://github.com/ustayready/CredSniper)                    |
| 📧 | **phishing-frenzy** | Framework Ruby on Rails para campañas de phishing (menos mantenido).          | FOSS        | [GitHub](https://github.com/pentestgeek/phishing-frenzy)              |

---

## V. 🛠️ Herramientas y Frameworks de Apoyo

Utilidades que complementan el análisis o la simulación.

### Herramientas OSINT para Contexto de Phishing

| Icon | Herramienta     | Descripción Clave                                                         | Modelo      | Link                                                 |
| :--: | :-------------- | :------------------------------------------------------------------------ | :---------- | :--------------------------------------------------- |
| 🔍 | **Maltego** | Potente plataforma gráfica para análisis de relaciones y OSINT.           | Freemium/Comercial | [maltego.com](https://www.maltego.com/)            |
| 🕷️ | **SpiderFoot** | Herramienta de automatización OSINT (auto-alojada o cloud).             | FOSS/Comercial | [spiderfoot.net](https://www.spiderfoot.net/)        |
| 🌐 | **theHarvester** | Recopila emails, subdominios, hosts, etc. desde fuentes públicas.       | FOSS        | [GitHub](https://github.com/laramies/theHarvester)   |
| 👤 | **Sherlock** | Busca nombres de usuario en múltiples redes sociales.                     | FOSS        | [GitHub](https://github.com/sherlock-project/sherlock) |
| 🗺️ | **Recon-ng** | Framework modular OSINT escrito en Python.                              | FOSS        | [GitHub](https://github.com/lanmaster53/recon-ng)    |

### Frameworks Generales de Seguridad

| Icon | Herramienta        | Descripción Clave                                                                 | Modelo      | Link                                                      |
| :--: | :----------------- | :-------------------------------------------------------------------------------- | :---------- | :-------------------------------------------------------- |
| 💥 | **Metasploit Framework** | Plataforma #1 para desarrollo y ejecución de exploits (incluye módulos auxiliares útiles). | FOSS/Comercial | [metasploit.com](https://www.metasploit.com/)             |
| 👁️ | **BeEF (Browser Exploitation Framework)** | Framework para controlar navegadores remotamente (útil para analizar kits de phishing). | FOSS        | [beefproject.com](https://beefproject.com/)               |
| ⚡ | **Cobalt Strike** | Plataforma comercial para simulación de adversarios (Red Teaming).                  | Comercial   | [cobaltstrike.com](https://www.cobaltstrike.com/)         |

---

## VI. 📚 Aprendizaje y Recursos Adicionales

Para profundizar y mantenerse actualizado.

### Ejemplos de Flujos de Trabajo (Ideas)

* **Análisis Rápido de URL Sospechosa:** `URL -> URLScan.io / VirusTotal -> Revisar resultados / Categorización.`
* **Análisis de Email de Phishing:** `Obtener EML -> Analizar Cabeceras (MxToolbox) -> Extraer IOCs (URLs, IPs, Hashes) -> Verificar IOCs (VirusTotal, AbuseIPDB, PhishTank) -> Analizar Adjuntos/URLs en Sandbox (Any.Run, Hybrid Analysis).`
* **Investigación de Campaña:** `Identificar Patrón (Asunto, Remitente, Kit Phishing) -> Usar IOCs para buscar en Threat Intel (MISP, PhishStats) -> Usar OSINT para investigar infraestructura (Maltego, Recon-ng).`

### Lecturas Recomendadas y Artículos

* [APWG Phishing Activity Trends Reports](https://apwg.org/trendsreports/) - Informes trimestrales sobre tendencias de phishing.
* [Blogs de Empresas de Seguridad](https://example.com/) - (Añadir enlaces a blogs relevantes: Proofpoint, Cofense, Akamai, Cisco Talos, Mandiant, etc.)
* [Phishing.org](https://www.phishing.org/) - Información general sobre phishing.
* [MITRE ATT&CK - Initial Access - Phishing (T1566)](https://attack.mitre.org/techniques/T1566/) - Descripción técnica de la táctica.

### Listas "Awesome" Relacionadas

* [awesome-incident-response](https://github.com/meirwah/awesome-incident-response)
* [awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)
* [awesome-osint](https://github.com/jivoi/awesome-osint)
* [awesome-security](https://github.com/sbilly/awesome-security)
* [awesome-soc](https://github.com/cyb3rxp/awesome-soc)

---

## VII. 🤝 Comunidad

¡Este repositorio es para la comunidad!

### Guía de Contribución

Agradecemos enormemente las contribuciones. Para asegurar la calidad:

1.  **Busca Duplicados:** Antes de añadir algo, asegúrate de que no exista ya.
2.  **Relevancia:** Asegúrate de que la herramienta/recurso esté directamente relacionado con el análisis, detección o prevención de phishing.
3.  **Información Completa:** Proporciona un enlace funcional, una descripción clara y concisa, y si es posible, el modelo (FOSS, Comercial, etc.).
4.  **Formato:** Sigue el formato Markdown existente (tablas, iconos si procede).
5.  **Crea un Pull Request:** Haz un fork, crea una rama descriptiva y envía un PR detallando tus cambios.

> **Preferimos Calidad sobre Cantidad.** Herramientas bien mantenidas y reconocidas son prioritarias.

### Código de Conducta

Esperamos que todos los participantes sigan un código de conducta que fomente un ambiente abierto y respetuoso. (Puedes enlazar a uno estándar como el [Contributor Covenant](https://www.contributor-covenant.org/)).

### Licencia

Este trabajo se distribuye bajo la licencia [Creative Commons Zero v1.0 Universal](LICENSE) (CC0 1.0). Puedes copiar, modificar y distribuir la obra, incluso con fines comerciales, sin pedir permiso.

[![CC0](https://licensebuttons.net/p/zero/1.0/88x31.png)](https://creativecommons.org/publicdomain/zero/1.0/)

---

*Creado con ❤️ por la comunidad y curado por [Nervi0zz0]*
