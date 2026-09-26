# Stage 2 — Pod Security Admission (PSA)

**Concept.** Stage 1 relied on the pod's author writing a good `securityContext`. PSA
is a built-in gate in the API server: label a namespace with a security level, and any
pod that doesn't meet it is **refused at creation**. Enforcement moves from the author
to the namespace.

Pick a **mode** and a **level**, both as namespace labels:

| Mode | Effect |
|---|---|
| `enforce` | Rejects the pod outright. |
| `warn` | Allows it, prints a warning. |
| `audit` | Allows it, records an audit annotation. |

| Level | Meaning |
|---|---|
| `privileged` | No restrictions (the default). |
| `baseline` | Blocks the obviously dangerous (privileged, host namespaces, hostPath). |
| `restricted` | Requires the full Stage 1 hardening (non-root, drop ALL, seccomp, no privilege escalation). |

## How the check works

PSA is an **admission controller, not a scanner**. It does not read your file or inspect
the image for vulnerabilities. When any pod-creating request reaches the API server, PSA
compares the pod's **spec fields** against a fixed, versioned ruleset for the level,
*before* the object is stored in etcd. For `restricted` it checks, among others:

| It checks | Must be |
|---|---|
| `securityContext.runAsNonRoot` | `true` |
| `securityContext.allowPrivilegeEscalation` | `false` |
| `securityContext.capabilities.drop` | contains `ALL` |
| `securityContext.seccompProfile.type` | `RuntimeDefault` or `Localhost` |
| privileged / host namespaces / hostPath | not present |

Compliant field values → admitted. Anything missing → `Forbidden`. It's a hardcoded
field checklist (the Kubernetes "Pod Security Standards"), applied cluster-side, so it
holds no matter who or what creates the pod.

## Lock a namespace and watch it reject a weak pod

​```powershell
kubectl create ns s2-psa
kubectl label ns s2-psa pod-security.kubernetes.io/enforce=restricted
kubectl apply -f s2-weak-pod.yaml
​```

`s2-weak-pod.yaml` — a plain pod, no `securityContext`:

​```yaml
apiVersion: v1
kind: Pod
metadata:
  name: needs-hardening
  namespace: s2-psa
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
​```

Result: a `Forbidden` error listing each unmet requirement. The pod is never created.

## The same gate admits a hardened pod

`s2-hardened-pod.yaml` — the Stage 1 hardening, which meets `restricted`:

​```yaml
apiVersion: v1
kind: Pod
metadata:
  name: hardened
  namespace: s2-psa
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
​```

​```powershell
kubectl apply -f s2-hardened-pod.yaml   # pod/hardened created — passes the gate
kubectl delete ns s2-psa                # cleanup
​```