"""
Tests for src/forensic_extension.py helper functions.
"""
import pytest
from unittest.mock import patch, MagicMock
import socket
import ssl

from src.forensic_extension import (
    banner_grab,
    ssh_banner,
    fetch_http_headers,
    fetch_tls_info,
    nmap_service_scan,
    safe_http_enum_well_known
)


class TestBannerGrab:
    """Tests for the banner_grab function."""

    def test_banner_grab_success(self):
        """Test successful banner grab with mocked socket."""
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.recv.return_value = b"SSH-2.0-OpenSSH_8.4\r\n"
            
            result = banner_grab("192.168.1.1", 22, timeout=2.0)
            
            assert result == "SSH-2.0-OpenSSH_8.4"
            mock_sock_instance.connect.assert_called_once_with(("192.168.1.1", 22))
            mock_sock_instance.settimeout.assert_called_once_with(2.0)

    def test_banner_grab_with_send_bytes(self):
        """Test banner grab with probe bytes."""
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.recv.return_value = b"220 SMTP Server ready\r\n"
            
            result = banner_grab("192.168.1.1", 25, send_bytes=b"EHLO test\r\n")
            
            assert result == "220 SMTP Server ready"
            mock_sock_instance.sendall.assert_called_once_with(b"EHLO test\r\n")

    def test_banner_grab_connection_refused(self):
        """Test banner grab when connection is refused."""
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.connect.side_effect = ConnectionRefusedError()
            
            result = banner_grab("192.168.1.1", 9999)
            
            assert result is None

    def test_banner_grab_timeout(self):
        """Test banner grab when connection times out."""
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.connect.side_effect = socket.timeout()
            
            result = banner_grab("192.168.1.1", 22)
            
            assert result is None

    def test_banner_grab_socket_closed(self):
        """Test that socket is always closed."""
        with patch('socket.socket') as mock_socket:
            mock_sock_instance = MagicMock()
            mock_socket.return_value = mock_sock_instance
            mock_sock_instance.recv.return_value = b"banner"
            
            banner_grab("192.168.1.1", 22)
            
            mock_sock_instance.close.assert_called_once()


class TestSshBanner:
    """Tests for the ssh_banner function."""

    def test_ssh_banner_success(self):
        """Test SSH banner retrieval."""
        with patch('src.forensic_extension.banner_grab') as mock_banner:
            mock_banner.return_value = "SSH-2.0-OpenSSH_7.9"
            
            result = ssh_banner("192.168.1.1", port=22)
            
            assert result == "SSH-2.0-OpenSSH_7.9"
            mock_banner.assert_called_once_with("192.168.1.1", 22, timeout=3.0)

    def test_ssh_banner_custom_timeout(self):
        """Test SSH banner with custom timeout."""
        with patch('src.forensic_extension.banner_grab') as mock_banner:
            mock_banner.return_value = "SSH-2.0-dropbear"
            
            result = ssh_banner("10.0.0.1", port=2222, timeout=5.0)
            
            mock_banner.assert_called_once_with("10.0.0.1", 2222, timeout=5.0)


class TestFetchHttpHeaders:
    """Tests for the fetch_http_headers function."""

    def test_fetch_http_headers_success(self):
        """Test successful HTTP header fetch."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {
                "Server": "nginx/1.18.0",
                "X-Powered-By": "PHP/7.4",
                "Content-Type": "text/html"
            }
            mock_response.text = "<html><head><title>Test</title></head></html>"
            mock_get.return_value = mock_response
            
            result = fetch_http_headers("192.168.1.1", port=80)
            
            assert result["status_code"] == 200
            assert result["server"] == "nginx/1.18.0"
            assert result["x_powered_by"] == "PHP/7.4"
            assert "timestamp" in result

    def test_fetch_http_headers_https(self):
        """Test HTTPS header fetch."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {"Server": "Apache"}
            mock_response.text = ""
            mock_get.return_value = mock_response
            
            fetch_http_headers("192.168.1.1", port=443, use_https=True)
            
            args, kwargs = mock_get.call_args
            assert args[0].startswith("https://")

    def test_fetch_http_headers_with_host_header(self):
        """Test HTTP headers with custom Host header."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {}
            mock_response.text = ""
            mock_get.return_value = mock_response
            
            fetch_http_headers("192.168.1.1", port=80, host_header="example.com")
            
            args, kwargs = mock_get.call_args
            assert kwargs["headers"]["Host"] == "example.com"

    def test_fetch_http_headers_error(self):
        """Test HTTP header fetch with error."""
        with patch('requests.get') as mock_get:
            mock_get.side_effect = Exception("Connection failed")
            
            result = fetch_http_headers("192.168.1.1", port=80)
            
            assert "error" in result
            assert "Connection failed" in result["error"]

    def test_fetch_http_headers_security_headers(self):
        """Test extraction of security-related headers."""
        with patch('requests.get') as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.headers = {
                "Server": "nginx",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'self'",
                "Content-Type": "text/html"  # Should not be in security_headers
            }
            mock_response.text = ""
            mock_get.return_value = mock_response
            
            result = fetch_http_headers("192.168.1.1", port=443)
            
            sec_headers = result["security_headers"]
            assert "Strict-Transport-Security" in sec_headers
            assert "X-Frame-Options" in sec_headers


class TestFetchTlsInfo:
    """Tests for the fetch_tls_info function."""

    def test_fetch_tls_info_success(self):
        """Test successful TLS info fetch."""
        with patch('socket.create_connection') as mock_conn, \
             patch('ssl.create_default_context') as mock_ctx:
            
            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            
            mock_ssock = MagicMock()
            mock_ssl_context = MagicMock()
            mock_ctx.return_value = mock_ssl_context
            mock_ssl_context.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
            mock_ssl_context.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            
            mock_ssock.getpeercert.return_value = {
                "subject": [[("commonName", "example.com")]],
                "issuer": [[("commonName", "CA")]],
                "subjectAltName": [("DNS", "example.com")],
                "notBefore": "Jan  1 00:00:00 2024 GMT",
                "notAfter": "Dec 31 23:59:59 2024 GMT"
            }
            mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            
            result = fetch_tls_info("192.168.1.1", port=443)
            
            assert "cert_subject" in result
            assert "cert_issuer" in result
            assert "cipher" in result

    def test_fetch_tls_info_error(self):
        """Test TLS info fetch with connection error."""
        with patch('socket.create_connection') as mock_conn:
            mock_conn.side_effect = socket.timeout("Connection timed out")
            
            result = fetch_tls_info("192.168.1.1", port=443)
            
            assert "error" in result


class TestNmapServiceScan:
    """Tests for the nmap_service_scan function."""

    def test_nmap_service_scan_success(self):
        """Test successful nmap service scan."""
        with patch('src.forensic_extension.nmap') as mock_nmap, \
             patch('src.forensic_extension._HAS_NMAP', True):
            mock_scanner = MagicMock()
            mock_nmap.PortScanner.return_value = mock_scanner
            mock_scanner.all_hosts.return_value = ["192.168.1.1"]
            mock_scanner.__getitem__ = MagicMock(return_value={
                "tcp": {22: {"state": "open", "name": "ssh"}},
                "osmatch": []
            })
            
            result = nmap_service_scan("192.168.1.1")
            
            assert "services" in result or "error" not in result or "nmap_raw" in result

    def test_nmap_service_scan_not_available(self):
        """Test nmap scan when nmap library not available."""
        with patch('src.forensic_extension._HAS_NMAP', False):
            result = nmap_service_scan("192.168.1.1")
            
            assert "error" in result
            assert "not available" in result["error"]


class TestSafeHttpEnumWellKnown:
    """Tests for the safe_http_enum_well_known function."""

    def test_safe_http_enum_well_known(self):
        """Test enumeration of well-known paths."""
        with patch('src.forensic_extension.fetch_http_headers') as mock_fetch:
            mock_fetch.return_value = {
                "status_code": 200,
                "server": "nginx",
                "error": None
            }
            
            result = safe_http_enum_well_known("192.168.1.1", port=80)
            
            assert "/" in result
            assert "/robots.txt" in result
            assert "/server-status" in result
            assert "/.git/config" in result
            
            # Should have called fetch_http_headers for each path
            assert mock_fetch.call_count == 4

    def test_safe_http_enum_well_known_mixed_results(self):
        """Test enumeration with mixed status codes."""
        def mock_fetch_side_effect(ip, port, use_https, path, host_header, timeout):
            if path == "/":
                return {"status_code": 200, "server": "nginx", "error": None}
            elif path == "/robots.txt":
                return {"status_code": 404, "server": "nginx", "error": None}
            elif path == "/server-status":
                return {"status_code": 403, "server": "nginx", "error": None}
            else:
                return {"status_code": None, "server": None, "error": "Connection refused"}
        
        with patch('src.forensic_extension.fetch_http_headers', side_effect=mock_fetch_side_effect):
            result = safe_http_enum_well_known("192.168.1.1", port=80)
            
            assert result["/"]["status_code"] == 200
            assert result["/robots.txt"]["status_code"] == 404
            assert result["/server-status"]["status_code"] == 403
