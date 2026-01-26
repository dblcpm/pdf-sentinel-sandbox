# Known Security Issues

## CVE-2026-0994: Protobuf JSON Recursion Depth Bypass

**Status**: CANNOT BE FIXED (Dependency Conflict)  
**Severity**: Medium  
**Affected Package**: protobuf <= 6.33.4  
**Fixed In**: protobuf >= 7.0 (not yet released as stable)

### Description
The protobuf library has a JSON recursion depth bypass vulnerability (CVE-2026-0994) that affects all versions up to and including 6.33.4.

### Why This Cannot Be Fixed
- **Fix Requires**: protobuf >= 7.0  
- **Dependency Conflict**: streamlit (our core dependency) requires protobuf < 7.0  
- **Current Version**: We use protobuf 6.33.4 (latest compatible with streamlit)

### Mitigation
1. **Input Validation**: PDF Sentinel validates and limits input sizes to prevent denial of service attacks
2. **Monitoring**: We actively monitor for updates to both protobuf and streamlit
3. **Upgrade Path**: Once streamlit supports protobuf 7.x, we will immediately upgrade

### Resolution Timeline
- **Short Term**: No fix available due to dependency conflict
- **Medium Term**: Waiting for streamlit to support protobuf 7.x (estimated Q2-Q3 2026)
- **Long Term**: Will upgrade immediately when compatible versions are released

### Workaround
The vulnerability is temporarily ignored in our CI/CD pipeline (`pip-audit --ignore-vuln CVE-2026-0994`) with full documentation and tracking for future resolution.

### References
- [CVE-2026-0994](https://nvd.nist.gov/vuln/detail/CVE-2026-0994)
- [Protobuf Releases](https://github.com/protocolbuffers/protobuf/releases)
- [Streamlit Dependencies](https://github.com/streamlit/streamlit)

---

*Last Updated*: 2026-01-26  
*Next Review*: 2026-03-01 (or when streamlit/protobuf updates are released)
