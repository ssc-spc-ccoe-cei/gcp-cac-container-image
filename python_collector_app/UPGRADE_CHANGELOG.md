# Upgrade Changelog

## [2026-02-??] Python Package & Routine Maintenance

**Status:** In Progress

**Infrastructure Components:**
| Component | Previous Version | New Version | Notes |
| :--- | :--- | :--- | :--- |
| **Cloud SDK** | `556.0.0-alpine` | `556.0.0-alpine` | Verified Stable / No Change |
| **OPA** | `v1.13.1` | `v1.13.1` | Verified Stable / No Change |
| **Python Runtime** | `3.12.12` | `3.12.12` | Matches Alpine 3.21 |

**Python Package Updates:**
| Package | Previous | New |
| :--- | :--- | :--- |
| `anyio` | 4.11.0 | **4.12.1** |
| `asgiref` | 3.10.0 | **3.11.1** |
| `certifi` | 2025.10.5 | **2026.1.4** |
| `click` | 8.3.0 | **8.3.1** |
| `cryptography` | 46.0.3 | **46.0.5** |
| `google-api-core` | 2.27.0 | **2.30.0** |
| `google-api-python-client` | 2.185.0 | **2.190.0** |
| `google-auth` | 2.41.1 | **2.48.0** |
| `google-auth-httplib2` | 0.2.0 | **0.3.0** |
| `google-cloud-appengine-logging` | 1.7.0 | **1.8.0** |
| `google-cloud-asset` | 4.1.0 | **4.2.0** |
| `google-cloud-core` | 2.4.3 | **2.5.0** |
| `google-cloud-logging` | 3.12.1 | **3.13.0** |
| `google-cloud-org-policy` | 1.15.0 | **1.16.1** |
| `google-cloud-os-config` | 1.22.0 | **1.23.0** |
| `google-cloud-securitycenter` | 1.41.0 | **1.42.0** |
| `google-cloud-storage` | 3.4.1 | **3.9.0** |
| `google-crc32c` | 1.7.1 | **1.8.0** |
| `google-resumable-media` | 2.7.2 | **2.8.0** |
| `googleapis-common-protos` | 1.71.0 | **1.72.0** |
| `grpcio` | 1.76.0 | **1.78.0** |
| `grpcio-status` | 1.76.0 | **1.78.0** |
| `httplib2` | 0.31.0 | **0.31.2** |
| `hypercorn` | 0.17.3 | **0.18.0** |
| `importlib-metadata` | 8.7.0 | **8.7.1** |
| `marshmallow` | 4.0.1 | **4.2.2** |
| `opentelemetry-api` | 1.38.0 | **1.39.1** |
| `proto-plus` | 1.26.1 | **1.27.1** |
| `protobuf` | 6.33.0 | **6.33.5** |
| `pyasn1` | 0.6.1 | **0.6.2** |
| `pycparser` | 2.23 | **3.0** |
| `pyparsing` | 3.2.5 | **3.3.2** |
| `urllib3` | 2.5.0 | **2.6.3** |
| `werkzeug` | 3.1.3 | **3.1.5** |
| `wsproto` | 1.2.0 | **1.3.2** |

**Removed:**
- `cachetools` (bundled in google-auth)
- `sniffio`
