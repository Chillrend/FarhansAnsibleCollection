import os
import requests
import socket
import ssl
import datetime
import concurrent.futures
import argparse
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings if you have internal self-signed certs
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# --- ENVIRONMENT LOADER ---
def load_env():
    """Custom light-weight .env parser to avoid installing python-dotenv."""
    env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip()
                    val = val.strip()
                    # Strip surrounding quotes if any
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    os.environ[key] = val

load_env()

# --- CONFIGURATION ---
ZONE_ID = os.environ.get("CLOUDFLARE_ZONE_ID", null)
API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN", null)

BYPASS_HEADER_NAME = os.environ.get("BYPASS_HEADER_NAME", null)
BYPASS_HEADER_VALUE = os.environ.get("BYPASS_HEADER_VALUE", null)

CF_API_URL = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records"
TARGET_CA = "GeoTrust TLS RSA CA G1"

# SMTP Mailgun Configuration
SMTP_SERVER = os.environ.get("MAILGUN_SMTP_SERVER", "smtp.mailgun.org")
SMTP_PORT = int(os.environ.get("MAILGUN_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("MAILGUN_SMTP_USER", "postmaster@yourdomain.com")
SMTP_PASSWORD = os.environ.get("MAILGUN_SMTP_PASSWORD", "")
FROM_EMAIL = os.environ.get("MAILGUN_FROM_EMAIL", "noreply@yourdomain.com")

def get_dns_records():
    """Fetch A and CNAME records from Cloudflare and filter obvious internal hosts."""
    headers = {
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
    params = {"per_page": 1000, "type": "A,CNAME"}

    print("Fetching DNS records from Cloudflare...")
    response = requests.get(CF_API_URL, headers=headers, params=params)
    response.raise_for_status()

    records = response.json().get("result", [])

    # Extract unique domain names
    raw_domains = list(set([record["name"] for record in records]))

    # Filter out known internal/VMware hosts by name
    clean_domains = []
    for domain in raw_domains:
        if "esxi" in domain.lower() or domain.lower() == "vc.pnj.ac.id":
            continue
        clean_domains.append(domain)

    print(f"Found {len(raw_domains)} records. Kept {len(clean_domains)} after basic name filtering.\n")
    return clean_domains

def get_issuer_common_name(cert):
    """Extracts the Common Name (CN) of the issuer from the cert dictionary."""
    try:
        for tuple_group in cert.get('issuer', []):
            for field in tuple_group:
                if field[0] == 'commonName':
                    return field[1]
    except Exception:
        pass
    return "Unknown CA"

def check_domain(domain):
    """Test SSL expiration, issuer, and HTTP reachability."""
    result = {
        "domain": domain,
        "ssl_days": None,
        "issuer": None,
        "http_status": None,
        "error": None,
        "is_geotrust": False
    }

    # 1. SSL CERTIFICATE CHECK
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Check the CA Issuer
                issuer_cn = get_issuer_common_name(cert)
                result["issuer"] = issuer_cn
                result["is_geotrust"] = (issuer_cn == TARGET_CA)

                # Calculate expiration using timezone-aware objects
                expire_date_str = cert['notAfter']
                expire_date = datetime.datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)

                result["ssl_days"] = (expire_date - now).days

    except Exception as e:
        result["error"] = f"SSL Error: {str(e)}"
        return result

    # 2. HTTP REACHABILITY CHECK
    url = f"https://{domain}"
    http_headers = {
        BYPASS_HEADER_NAME: BYPASS_HEADER_VALUE,
        "User-Agent": "PNJ-Internal-Audit/1.0"
    }

    try:
        resp = requests.get(url, headers=http_headers, timeout=3, verify=False, allow_redirects=False)
        if resp.status_code < 400:
            result["http_status"] = f"HTTP {resp.status_code} (OK)"
        elif resp.status_code in [401, 403]:
            result["http_status"] = f"HTTP {resp.status_code} (BLOCKED)"
        else:
            result["http_status"] = f"HTTP {resp.status_code}"
    except requests.exceptions.RequestException:
        result["http_status"] = "HTTP Timeout/Error"

    return result

def is_first_weekend():
    """Checks if today is Saturday or Sunday and falls within the first 7 days of the month."""
    now = datetime.datetime.now()
    # Saturday is 5, Sunday is 6 in datetime.weekday()
    return now.weekday() in [5, 6] and now.day <= 7

def generate_plaintext_report(summary, geotrust_expiring, geotrust_healthy, other_certs, failed_hosts):
    """Generates a clean text representation of the results."""
    lines = []
    lines.append("=" * 80)
    lines.append("               AUTO SSL SCANNER SCRIPT REPORT - FARHAN")
    lines.append(f"               Scan Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 80)
    lines.append("")
    lines.append("SUMMARY STATISTICS:")
    lines.append(f"  - Total Domains Scanned: {summary['total']}")
    lines.append(f"  - GeoTrust (Expiring Soon <= 30 Days): {len(geotrust_expiring)}")
    lines.append(f"  - GeoTrust (Healthy > 30 Days): {len(geotrust_healthy)}")
    lines.append(f"  - Other CA Certificates: {len(other_certs)}")
    lines.append(f"  - Failed / Unreachable Hosts: {len(failed_hosts)}")
    lines.append("")

    # 1. GeoTrust Expiring Soon
    lines.append("=" * 80)
    lines.append("🔴 GEOTRUST CERTIFICATES EXPIRING SOON (<= 30 DAYS)")
    lines.append("=" * 80)
    if geotrust_expiring:
        lines.append(f"{'DOMAIN':<38} | {'HTTP STATUS':<22} | {'SSL EXPIRY':<15}")
        lines.append("-" * 80)
        for r in geotrust_expiring:
            lines.append(f"{r['domain']:<38} | {str(r['http_status']):<22} | {r['ssl_days']} days")
    else:
        lines.append("No GeoTrust certificates are expiring soon. All healthy!")
    lines.append("")

    # 2. GeoTrust Healthy
    lines.append("=" * 80)
    lines.append("🟢 HEALTHY GEOTRUST CERTIFICATES (> 30 DAYS)")
    lines.append("=" * 80)
    if geotrust_healthy:
        lines.append(f"{'DOMAIN':<38} | {'HTTP STATUS':<22} | {'SSL EXPIRY':<15}")
        lines.append("-" * 80)
        for r in geotrust_healthy:
            lines.append(f"{r['domain']:<38} | {str(r['http_status']):<22} | {r['ssl_days']} days")
    else:
        lines.append("No domains matching this CA category.")
    lines.append("")

    # 3. Other Certificates
    lines.append("=" * 80)
    lines.append("🔵 OTHER CA CERTIFICATES INSTALLED")
    lines.append("=" * 80)
    if other_certs:
        lines.append(f"{'DOMAIN':<35} | {'HTTP STATUS':<20} | {'SSL EXPIRY':<12} | {'ISSUER'}")
        lines.append("-" * 80)
        for r in other_certs:
            days_str = f"{r['ssl_days']} days"
            lines.append(f"{r['domain']:<35} | {str(r['http_status']):<20} | {days_str:<12} | {str(r['issuer'])}")
    else:
        lines.append("No domains with other CA certificates found.")
    lines.append("")

    # 4. Failed / Unreachable
    lines.append("=" * 80)
    lines.append("⚪ FAILED / UNREACHABLE HOSTS")
    lines.append("=" * 80)
    if failed_hosts:
        lines.append(f"{'DOMAIN':<38} | {'HTTP STATUS':<20} | {'ERROR / DETAILS'}")
        lines.append("-" * 80)
        for r in failed_hosts:
            err = r["error"] or "Unknown Connection Error"
            # Truncate details if they are too long for alignment
            if len(err) > 40:
                err = err[:37] + "..."
            lines.append(f"{r['domain']:<38} | {str(r['http_status'] or 'N/A'):<20} | {err}")
    else:
        lines.append("No failed or unreachable hosts found.")
    lines.append("")

    return "\n".join(lines)

def generate_html_report(summary, geotrust_expiring, geotrust_healthy, other_certs, failed_hosts):
    """Generates a beautifully structured HTML email report."""
    now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # CSS template
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #2d3748;
    background-color: #f7fafc;
    margin: 0;
    padding: 20px;
  }}
  .container {{
    max-width: 900px;
    margin: 0 auto;
    background: #ffffff;
    padding: 25px;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
    border: 1px solid #e2e8f0;
  }}
  h1 {{
    color: #1a365d;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 12px;
    font-size: 22px;
    margin-top: 0;
    text-align: center;
  }}
  h2 {{
    color: #2c5282;
    font-size: 16px;
    margin-top: 30px;
    margin-bottom: 12px;
    border-bottom: 1px solid #edf2f7;
    padding-bottom: 5px;
  }}
  .summary-cards {{
    display: flex;
    gap: 12px;
    margin-bottom: 25px;
    margin-top: 20px;
  }}
  .card {{
    flex: 1;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    padding: 12px;
    border-radius: 6px;
    text-align: center;
  }}
  .card-value {{
    font-size: 22px;
    font-weight: bold;
    color: #1a202c;
    margin-top: 4px;
  }}
  .card-title {{
    font-size: 10px;
    text-transform: uppercase;
    color: #718096;
    letter-spacing: 0.5px;
  }}
  .card.critical {{
    background: #fff5f5;
    border-color: #feb2b2;
  }}
  .card.critical .card-value {{
    color: #e53e3e;
  }}
  .card.healthy {{
    background: #f0fff4;
    border-color: #9ae6b4;
  }}
  .card.healthy .card-value {{
    color: #38a169;
  }}
  .card.other {{
    background: #ebf8ff;
    border-color: #90cdf4;
  }}
  .card.other .card-value {{
    color: #3182ce;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
    font-size: 13px;
  }}
  th, td {{
    padding: 8px 10px;
    text-align: left;
    border-bottom: 1px solid #edf2f7;
  }}
  th {{
    background-color: #f7fafc;
    color: #4a5568;
    font-weight: 600;
  }}
  tr.warning-row {{
    background-color: #fffaf0;
  }}
  tr.critical-row {{
    background-color: #fff5f5;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 6px;
    font-size: 10px;
    font-weight: bold;
    border-radius: 4px;
    text-transform: uppercase;
  }}
  .badge-critical {{
    background-color: #fed7d7;
    color: #9b2c2c;
  }}
  .badge-warning {{
    background-color: #feebc8;
    color: #9c4221;
  }}
  .badge-healthy {{
    background-color: #c6f6d5;
    color: #22543d;
  }}
  .badge-neutral {{
    background-color: #edf2f7;
    color: #4a5568;
  }}
  .error-text {{
    color: #e53e3e;
    font-family: monospace;
    font-size: 11px;
  }}
  .footer {{
    margin-top: 45px;
    font-size: 11px;
    color: #a0aec0;
    text-align: center;
    border-top: 1px solid #edf2f7;
    padding-top: 15px;
  }}
</style>
</head>
<body>
<div class="container">
  <h1>Auto SSL Scanner Script Report - Farhan</h1>
  <div style="text-align: center; font-size: 12px; color: #718096; margin-top: -8px;">Scan Executed: {now_str}</div>

  <div class="summary-cards">
    <div class="card">
      <div class="card-title">Total Scanned</div>
      <div class="card-value">{summary['total']}</div>
    </div>
    <div class="card {'critical' if len(geotrust_expiring) > 0 else ''}">
      <div class="card-title">Expiring GeoTrust</div>
      <div class="card-value">{len(geotrust_expiring)}</div>
    </div>
    <div class="card healthy">
      <div class="card-title">Healthy GeoTrust</div>
      <div class="card-value">{len(geotrust_healthy)}</div>
    </div>
    <div class="card other">
      <div class="card-title">Other CAs</div>
      <div class="card-value">{len(other_certs)}</div>
    </div>
    <div class="card">
      <div class="card-title">Failed/Unreachable</div>
      <div class="card-value">{len(failed_hosts)}</div>
    </div>
  </div>
"""

    # 1. GeoTrust Expiring Soon
    html += "<h2>🔴 GEOTRUST CERTIFICATES EXPIRING SOON (&le; 30 DAYS)</h2>"
    if geotrust_expiring:
        html += """<table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>HTTP Status</th>
              <th>Days Left</th>
              <th>Alert</th>
            </tr>
          </thead>
          <tbody>"""
        for r in geotrust_expiring:
            days = r['ssl_days']
            badge_cls = "badge-critical" if days <= 15 else "badge-warning"
            badge_txt = "CRITICAL" if days <= 15 else "WARNING"
            row_cls = "critical-row" if days <= 15 else "warning-row"
            html += f"""
            <tr class="{row_cls}">
              <td><strong>{r['domain']}</strong></td>
              <td>{r['http_status']}</td>
              <td>{days} days</td>
              <td><span class="badge {badge_cls}">{badge_txt}</span></td>
            </tr>"""
        html += "</tbody></table>"
    else:
        html += "<p style='color: #2f855a; font-size: 13px;'>✓ No GeoTrust certificates are expiring within 30 days.</p>"

    # 2. GeoTrust Healthy
    html += "<h2>🟢 HEALTHY GEOTRUST CERTIFICATES (&gt; 30 DAYS)</h2>"
    if geotrust_healthy:
        html += """<table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>HTTP Status</th>
              <th>Days Left</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>"""
        for r in geotrust_healthy:
            html += f"""
            <tr>
              <td>{r['domain']}</td>
              <td>{r['http_status']}</td>
              <td>{r['ssl_days']} days</td>
              <td><span class="badge badge-healthy">HEALTHY</span></td>
            </tr>"""
        html += "</tbody></table>"
    else:
        html += "<p style='color: #718096; font-size: 13px;'>No domains currently matching this CA category.</p>"

    # 3. Other Certificates
    html += "<h2>🔵 OTHER CA CERTIFICATES INSTALLED</h2>"
    if other_certs:
        html += """<table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>HTTP Status</th>
              <th>Days Left</th>
              <th>Certificate Issuer</th>
            </tr>
          </thead>
          <tbody>"""
        for r in other_certs:
            html += f"""
            <tr>
              <td>{r['domain']}</td>
              <td>{r['http_status']}</td>
              <td>{r['ssl_days']} days</td>
              <td><span class="badge badge-neutral">{r['issuer']}</span></td>
            </tr>"""
        html += "</tbody></table>"
    else:
        html += "<p style='color: #718096; font-size: 13px;'>No alternative CA certificates found.</p>"

    # 4. Failed / Unreachable
    html += "<h2>⚪ FAILED / UNREACHABLE HOSTS</h2>"
    if failed_hosts:
        html += """<table>
          <thead>
            <tr>
              <th>Domain</th>
              <th>HTTP Status</th>
              <th>Error Details</th>
            </tr>
          </thead>
          <tbody>"""
        for r in failed_hosts:
            html += f"""
            <tr>
              <td style="color: #4a5568;">{r['domain']}</td>
              <td>{r['http_status'] or 'N/A'}</td>
              <td><span class="error-text">{r['error']}</span></td>
            </tr>"""
        html += "</tbody></table>"
    else:
        html += "<p style='color: #2f855a; font-size: 13px;'>✓ No failed or unreachable domains detected.</p>"

    # Footer
    html += f"""
  <div class="footer">
    <p>This scan was generated headlessly by the Auto SSL Scanner Script.<br>
    Configured for upatik@pnj.ac.id and farhan.hanif@pnj.ac.id.</p>
  </div>
</div>
</body>
</html>
"""
    return html

def send_email_report(subject, html_content, text_content):
    """Sends the report to configured recipients via Mailgun SMTP."""
    if not SMTP_PASSWORD:
        print("[WARNING] MAILGUN_SMTP_PASSWORD is not set. Skipping email report dispatch.")
        return False

    recipients = ["upatik@pnj.ac.id", "farhan.hanif@pnj.ac.id"]

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = FROM_EMAIL
    msg['To'] = ", ".join(recipients)

    # Attach alternate parts
    part1 = MIMEText(text_content, 'plain')
    part2 = MIMEText(html_content, 'html')
    msg.attach(part1)
    msg.attach(part2)

    try:
        print(f"Connecting to SMTP server {SMTP_SERVER}:{SMTP_PORT}...")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        if SMTP_PORT == 587:
            server.starttls()
            server.ehlo()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.sendmail(FROM_EMAIL, recipients, msg.as_string())
        server.quit()
        print(f"SUCCESS: Email report sent successfully to: {', '.join(recipients)}")
        return True
    except Exception as e:
        print(f"ERROR: Failed to send email report via SMTP: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Auto SSL Scanner Script with Mailgun Reporting")
    parser.add_argument("--force-email", action="store_true", help="Force email dispatch even if it's not the first weekend.")
    args = parser.parse_args()

    try:
        domains = get_dns_records()
    except Exception as e:
        print(f"Failed to fetch records: {e}")
        return

    geotrust_expiring = []
    geotrust_healthy = []
    other_certs = []
    failed_hosts = []

    print(f"Checking SSL and reachability for {len(domains)} domains...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_domain, domain): domain for domain in domains}

        completed_count = 0
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            completed_count += 1
            if completed_count % 50 == 0 or completed_count == len(domains):
                print(f"  Progress: {completed_count}/{len(domains)} checked...")

            if res["error"]:
                failed_hosts.append(res)
            elif res["is_geotrust"]:
                if res["ssl_days"] <= 30:
                    geotrust_expiring.append(res)
                else:
                    geotrust_healthy.append(res)
            else:
                other_certs.append(res)

    # Sort groups
    geotrust_expiring.sort(key=lambda x: x["ssl_days"])
    geotrust_healthy.sort(key=lambda x: x["ssl_days"])
    other_certs.sort(key=lambda x: x["ssl_days"])
    failed_hosts.sort(key=lambda x: x["domain"])

    summary = {
        "total": len(domains),
        "geotrust_expiring": len(geotrust_expiring),
        "geotrust_healthy": len(geotrust_healthy),
        "other_certs": len(other_certs),
        "failed_hosts": len(failed_hosts)
    }

    # Generate Reports
    plaintext_report = generate_plaintext_report(summary, geotrust_expiring, geotrust_healthy, other_certs, failed_hosts)
    html_report = generate_html_report(summary, geotrust_expiring, geotrust_healthy, other_certs, failed_hosts)

    # 1. Print report to standard output
    print("\n" + plaintext_report)

    # 2. Save latest report to log files
    log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssl_scan.log")
    history_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssl_scan_history.log")

    try:
        with open(log_file_path, "w") as f:
            f.write(plaintext_report)
        print(f"Latest report written to {log_file_path}")
    except Exception as e:
        print(f"Failed to write log file: {e}")

    try:
        now_str = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(history_file_path, "a") as f:
            f.write(f"{now_str} - Scanned: {summary['total']}, GeoTrust Expiring: {summary['geotrust_expiring']}, GeoTrust Healthy: {summary['geotrust_healthy']}, Other CAs: {summary['other_certs']}, Failed: {summary['failed_hosts']}\n")
        print(f"Summary appended to {history_file_path}")
    except Exception as e:
        print(f"Failed to append to history log: {e}")

    # 3. Determine if email report should be dispatched
    should_email = args.force_email or is_first_weekend()
    if should_email:
        print("\nSending email report...")
        send_email_report(
            subject="Auto SSL Scanner Script Report - Farhan",
            html_content=html_report,
            text_content=plaintext_report
        )
    else:
        print("\nEmail conditions not met (not first weekend of the month, and --force-email flag is absent).")

if __name__ == "__main__":
    main()
