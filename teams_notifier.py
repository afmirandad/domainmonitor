import requests
import json
import os
from datetime import datetime

class TeamsNotifier:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or os.getenv('TEAMS_WEBHOOK_URL')
        
    def send_domain_alert(self, domain, status, expiration_date, days_left):
        """Envía alerta de dominio a Teams"""
        if not self.webhook_url:
            print("Teams webhook URL not configured")
            return
            
        color = self._get_theme_color(days_left)
        urgency_emoji = self._get_urgency_emoji(days_left)
        
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Domain Alert: {domain}",
            "originator": "Domain Monitor Bot",
            "sections": [{
                "activityTitle": f"{urgency_emoji} Domain Expiration Alert",
                "activitySubtitle": f"🤖 **Domain Monitor Bot** | Domain: **{domain}**",
                "activityImage": "https://via.placeholder.com/64x64/0078d4/ffffff?text=DM",
                "facts": [
                    {
                        "name": "Status:",
                        "value": status
                    },
                    {
                        "name": "Expiration Date:",
                        "value": expiration_date.strftime("%Y-%m-%d") if isinstance(expiration_date, datetime) else str(expiration_date)
                    },
                    {
                        "name": "Days Remaining:",
                        "value": f"**{days_left} days**"
                    },
                    {
                        "name": "Priority:",
                        "value": self._get_priority_text(days_left)
                    }
                ],
                "markdown": True
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "🔍 Check WHOIS Info",
                "targets": [{
                    "os": "default",
                    "uri": f"https://whois.net/{domain}"
                }]
            }]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(message),
                timeout=10
            )
            response.raise_for_status()
            print(f"✅ Teams notification sent for {domain}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error sending Teams notification: {e}")
    
    def _get_theme_color(self, days_left):
        """Retorna color basado en días restantes"""
        if days_left <= 7:
            return "FF0000"  # Red - Crítico
        elif days_left <= 30:
            return "FFA500"  # Orange - Advertencia
        elif days_left <= 60:
            return "FFFF00"  # Yellow - Precaución
        else:
            return "00FF00"  # Green - OK
    
    def _get_urgency_emoji(self, days_left):
        """Retorna emoji basado en urgencia"""
        if days_left <= 7:
            return "🚨"
        elif days_left <= 30:
            return "⚠️"
        elif days_left <= 60:
            return "🔔"
        else:
            return "ℹ️"
    
    def _get_priority_text(self, days_left):
        """Retorna texto de prioridad"""
        if days_left <= 7:
            return "🔴 CRITICAL - Renew immediately!"
        elif days_left <= 30:
            return "🟡 HIGH - Schedule renewal soon"
        elif days_left <= 60:
            return "🟢 MEDIUM - Plan renewal"
        else:
            return "🔵 LOW - Monitor"
    
    def send_test_message(self):
        """Envía mensaje de prueba"""
        if not self.webhook_url:
            print("❌ Teams webhook URL not configured")
            return
            
        test_message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "Domain Monitor Test",
            "originator": "Domain Monitor Bot",
            "sections": [{
                "activityTitle": "✅ Domain Monitor Connected",
                "activitySubtitle": "🤖 **Domain Monitor Bot** | Connection Test",
                "activityImage": "https://via.placeholder.com/64x64/0078d4/ffffff?text=DM",
                "text": "🎉 Your domain monitoring system is now connected to Teams!",
                "facts": [
                    {
                        "name": "System:",
                        "value": "Domain Monitor v1.0"
                    },
                    {
                        "name": "Status:",
                        "value": "✅ Active"
                    },
                    {
                        "name": "Test Time:",
                        "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                ]
            }]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(test_message),
                timeout=10
            )
            response.raise_for_status()
            print("✅ Test message sent to Teams successfully")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error sending test message: {e}")

    def send_summary_report(self, domains_data):
        """Envía reporte resumen de múltiples dominios"""
        if not self.webhook_url:
            print("Teams webhook URL not configured")
            return
            
        # Separar dominios por prioridad
        critical = [d for d in domains_data if d['days_left'] <= 7]
        warning = [d for d in domains_data if 7 < d['days_left'] <= 30]
        ok = [d for d in domains_data if d['days_left'] > 30]
        
        # Crear facts para el reporte
        facts = [
            {
                "name": "🚨 Critical (≤7 days):",
                "value": f"{len(critical)} domains"
            },
            {
                "name": "⚠️ Warning (8-30 days):",
                "value": f"{len(warning)} domains"
            },
            {
                "name": "✅ OK (>30 days):",
                "value": f"{len(ok)} domains"
            }
        ]
        
        # Agregar detalles de dominios críticos
        if critical:
            critical_details = ", ".join([f"{d['domain']} ({d['days_left']}d)" for d in critical[:3]])
            facts.append({
                "name": "Critical domains:",
                "value": critical_details + ("..." if len(critical) > 3 else "")
            })
        
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if critical else ("FFA500" if warning else "00FF00"),
            "summary": "Domain Monitor Daily Report",
            "originator": "Domain Monitor Bot",
            "sections": [{
                "activityTitle": "📊 Daily Domain Status Report",
                "activitySubtitle": f"🤖 **Domain Monitor Bot** | Monitoring {len(domains_data)} domains",
                "activityImage": "https://via.placeholder.com/64x64/0078d4/ffffff?text=DM",
                "facts": facts,
                "markdown": True
            }]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(message),
                timeout=10
            )
            response.raise_for_status()
            print("✅ Summary report sent to Teams successfully")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error sending summary report: {e}")

    def send_port_scan_alert(self, domain, open_ports, closed_ports):
        """Envía alerta de escaneo de puertos a Teams"""
        if not self.webhook_url:
            print("Teams webhook URL not configured")
            return
            
        total_scanned = len(open_ports) + len(closed_ports)
        color = "FF0000" if len(open_ports) > 5 else "FFA500" if len(open_ports) > 0 else "00FF00"
        
        facts = [
            {
                "name": "🌐 Domain:",
                "value": domain
            },
            {
                "name": "📊 Ports Scanned:",
                "value": str(total_scanned)
            },
            {
                "name": "🟢 Open Ports:",
                "value": str(len(open_ports))
            },
            {
                "name": "🔴 Closed Ports:",
                "value": str(len(closed_ports))
            }
        ]
        
        if open_ports:
            facts.append({
                "name": "🔓 Open Port Details:",
                "value": ", ".join([f"{port['port']}/{port['protocol']}" for port in open_ports[:10]])
            })
        
        message = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color,
            "summary": f"Port Scan Alert: {domain}",
            "originator": "Domain Monitor Bot",
            "sections": [{
                "activityTitle": "🔍 Port Scan Results",
                "activitySubtitle": f"🤖 **Domain Monitor Bot** | Security scan for **{domain}**",
                "activityImage": "https://via.placeholder.com/64x64/0078d4/ffffff?text=DM",
                "facts": facts,
                "markdown": True
            }]
        }
        
        try:
            response = requests.post(
                self.webhook_url,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(message),
                timeout=10
            )
            response.raise_for_status()
            print(f"✅ Port scan alert sent for {domain}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error sending port scan alert: {e}")
