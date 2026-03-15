# Commercial Licensing

## Open Source Licence

Anya — both the analysis engine (`anya-security-core`) and the desktop GUI (`anya-gui`) — is
released under the **GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)**.

A full copy of the licence is available in [LICENSE.TXT](LICENSE.TXT) and at
<https://www.gnu.org/licenses/agpl-3.0.html>.

---

## What AGPL-3.0 Requires

The AGPL is a strong copyleft licence. Its key requirement, beyond the GPL, is the
**network use provision**: if you run a modified version of Anya as a service accessible
to users over a network (e.g. as part of a web application, API, or cloud platform), you
must make the complete corresponding source code of your modified version available to
those users under the AGPL.

In practical terms, AGPL means you **must** open-source your modifications if you:

- Embed Anya in a proprietary product or service.
- Offer analysis-as-a-service (AaaS) backed by Anya without releasing your integration code.
- Distribute a modified binary of Anya — even internally within an organisation — without
  providing the modified source to recipients.

If these requirements are incompatible with how you intend to use Anya, you need a
commercial licence.

---

## Commercial Licence

A commercial licence grants you the right to use Anya without the AGPL copyleft
obligations. It is intended for organisations that:

- Need to integrate Anya into a **closed-source** product, pipeline, or internal platform.
- Cannot or do not wish to open-source the code that interfaces with Anya.
- Are embedding Anya in a **commercial product** distributed to customers.
- Require contractual assurances beyond what the AGPL provides.

### What a Commercial Licence Covers

| Right | AGPL-3.0 | Commercial |
|---|---|---|
| Use Anya in open-source software | Yes | Yes |
| Use Anya in closed-source software | No (copyleft applies) | **Yes** |
| Offer Anya as a network service without source disclosure | No | **Yes** |
| Embed Anya in a redistributed commercial product | No (source must accompany) | **Yes** |
| Modify Anya without publishing changes | No | **Yes** |
| Priority support (future) | No | **Yes** |

A commercial licence does **not** grant ownership of the Anya source code or any
intellectual property beyond the rights described above.

### What a Commercial Licence Does Not Cover

- Reselling or sublicensing the Anya source code itself.
- Use of the Anya name or branding beyond what is required to identify the underlying
  component in your product documentation.
- Any warranty, express or implied, regarding fitness for a particular purpose. Anya is a
  static analysis tool; it does not guarantee detection of all malicious files.

---

## Pricing

Pricing is not published here. Commercial licensing is negotiated on a case-by-case basis
depending on use case, scale, and support requirements. Pricing decisions will be
formalised in a future version (v2) of this document.

---

## How to Enquire

If you believe you need a commercial licence, or if you are unsure whether your use case
falls within the AGPL, please reach out:

- **Email:** daniel@themalwarefiles.com
- **GitHub Discussions:** <https://github.com/elementmerc/anya/discussions>

Provide a brief description of your intended use case. We respond to all enquiries.

---

## Contributor Licensing

Contributions to Anya are accepted under the project's AGPL-3.0 licence. By submitting a
pull request or patch, you agree that your contribution may be licensed both under the
AGPL-3.0 (for open-source users) and under commercial licences issued to third parties.
This is standard practice for dual-licensed projects and ensures the project can be
sustainably maintained.

If you are not comfortable with this arrangement, please discuss it with the maintainer
before contributing.
