\# ARGUS-ONE



\## Passive Network Threat Intelligence \& Detection



ARGUS-ONE is a passive network threat detection system designed to provide visibility into isolated or critical infrastructure through \*\*unidirectional network monitoring\*\*.



The system analyzes normalized network-flow metadata without inspecting packet payloads and identifies suspicious behavioral patterns using a hybrid detection approach.



\---



\## 🚨 Problem Statement



Critical infrastructure requires strict network isolation to reduce security exposure. However, strong isolation can also reduce visibility into network traffic and make it difficult for security teams to identify suspicious activity.



ARGUS-ONE addresses this challenge by providing:



\- Passive network-flow monitoring

\- Unidirectional traffic visibility

\- Metadata-based threat detection

\- Automated threat classification

\- Real-time alert generation

\- Centralized security monitoring through a dashboard



The goal is to improve \*\*visibility and detection speed\*\* without creating a bidirectional communication path into the protected network.



\---



\## 🎯 Key Features



\- 🔒 Passive and unidirectional monitoring

\- 📡 Network-flow metadata analysis

\- 🤖 Hybrid ML/behavioral threat detection

\- 🚨 Automated alert generation

\- 📊 Real-time security dashboard

\- 💾 SQLite-based alert and flow storage

\- 🔄 REST APIs using FastAPI

\- 🧪 Automated end-to-end testing

\- ⚡ Multi-scale behavioral analysis

\- 🛡️ Payload-free detection



\---



\## 🏗️ System Architecture



```text

┌──────────────────────────────┐

│      Critical Network        │

│                              │

│   Network Traffic / Flows    │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              │ Unidirectional Flow Metadata

&#x20;              ▼

┌──────────────────────────────┐

│   Software Data-Diode        │

│       Prototype              │

│                              │

│  One-way monitoring path     │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│       FastAPI Backend        │

│                              │

│  Flow Ingestion              │

│  Validation                  │

│  Alert Management            │

│  Statistics                  │

│  API Layer                   │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│      ARGUS-ONE Detector      │

│                              │

│ Behavioral Feature Extraction│

│ Hybrid Detection Model       │

│ Temporal Analysis            │

│ Event Correlation            │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│          SQLite              │

│                              │

│ Flows + Alerts + Statistics  │

└──────────────┬───────────────┘

&#x20;              │

&#x20;              ▼

┌──────────────────────────────┐

│      React Dashboard         │

│                              │

│ Threats • Alerts • Flows     │

│ Statistics • System Status   │

└──────────────────────────────┘

