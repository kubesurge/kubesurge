<div align="center">
  <img src="https://raw.githubusercontent.com/kubesurge/kubesurge/main/assets/logo.png" width="200" alt="KubeSurge Logo" />
  <h1>KubeSurge</h1>
  <p><strong>Surgical, non-destructive diagnostic tooling for hardened enterprise Kubernetes clusters.</strong></p>
</div>

---

### 🔬 What is KubeSurge?

KubeSurge is a modern open-source organization dedicated to building production-grade, zero-touch infrastructure utilities. Our primary project, **[KubeSurge](https://github.com/kubesurge/kubesurge)**, enables SREs and developers to inject surgical diagnostics (such as `tcpdump`, `strace`, and native `.NET diagnostics` tools) into live, distroless, and hardened Kubernetes pods without restarting them, using zero local node disk resources.

### 🛡️ Core Values

* **Zero-Touch & Zero-Disk:** Diagnostics should be non-destructive and should never leave residual packet captures or memory dumps on node-local file systems.
* **Hardened Cluster Native:** Tools must work within the constraints of strict Pod Security Standards (PSS) and Admission Controllers (Kyverno, OPA Gatekeeper).
* **Auditable & Secure:** Every artifact is minimal, built in public multi-stage harvesters, and keylessly signed via Cosign for absolute supply-chain trust.

---

### 📦 Key Projects

* **[kubesurge](https://github.com/kubesurge/kubesurge)** — The core CLI utility and diagnostic container orchestration engine.
* **[debugpod](https://github.com/kubesurge/kubesurge/blob/main/Dockerfile.debugpod)** — Minimal, verified diagnostic payload container containing network, system, and managed .NET diagnostics.
