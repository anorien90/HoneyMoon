"""
Tests for src/entry.py SQLAlchemy models.
"""
import pytest
from datetime import datetime, timezone

from src.entry import Base, NetworkNode, Organization, AnalysisSession, PathHop, WebAccess, ISP, OutgoingConnection


class TestOrganization:
    """Tests for the Organization model."""

    def test_organization_creation(self, db_session):
        """Test creating an organization."""
        org = Organization(
            name="Test Org",
            name_normalized="test org",
            rdap={"provider": "Test Provider"},
            abuse_email="abuse@test.org",
            extra_data={}
        )
        db_session.add(org)
        db_session.commit()
        
        assert org.id is not None
        assert org.name == "Test Org"
        assert org.name_normalized == "test org"
        assert org.rdap == {"provider": "Test Provider"}
        assert org.abuse_email == "abuse@test.org"
        assert org.created_at is not None

    def test_organization_dict(self, sample_organization):
        """Test the Organization.dict() method."""
        org_dict = sample_organization.dict()
        
        assert org_dict["id"] == sample_organization.id
        assert org_dict["name"] == "Test Organization"
        assert org_dict["name_normalized"] == "test organization"
        assert org_dict["rdap"] == {"provider": "Test Provider"}
        assert org_dict["abuse_email"] == "abuse@test.org"
        assert "created_at" in org_dict
        assert org_dict["extra_data"] == {"note": "test org"}

    def test_organization_repr(self, sample_organization):
        """Test the Organization.__repr__() method."""
        repr_str = repr(sample_organization)
        assert "Organization" in repr_str
        assert str(sample_organization.id) in repr_str
        assert "Test Organization" in repr_str

    def test_organization_name_normalized_unique(self, db_session):
        """Test that name_normalized must be unique."""
        org1 = Organization(name="Org 1", name_normalized="same org")
        db_session.add(org1)
        db_session.commit()

        org2 = Organization(name="Org 2", name_normalized="same org")
        db_session.add(org2)
        
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()


class TestNetworkNode:
    """Tests for the NetworkNode model."""

    def test_network_node_creation(self, db_session, sample_organization):
        """Test creating a network node."""
        node = NetworkNode(
            ip="10.0.0.1",
            hostname="test.local",
            organization="Test Organization",
            organization_id=sample_organization.id,
            isp="Test ISP",
            asn="AS12345",
            country="US",
            city="NYC",
            latitude=40.7128,
            longitude=-74.0060,
            is_tor_exit=False,
            seen_count=1,
            extra_data={"test": True}
        )
        db_session.add(node)
        db_session.commit()
        
        assert node.ip == "10.0.0.1"
        assert node.hostname == "test.local"
        assert node.organization_id == sample_organization.id
        assert node.is_tor_exit is False
        assert node.first_seen is not None

    def test_network_node_dict(self, db_session, sample_network_node):
        """Test the NetworkNode.dict() method."""
        # Refresh to ensure relationship is loaded
        db_session.refresh(sample_network_node)
        node_dict = sample_network_node.dict()
        
        assert node_dict["ip"] == "192.168.1.1"
        assert node_dict["hostname"] == "test-host.local"
        assert node_dict["organization"] == "Test Organization"
        assert node_dict["country"] == "United States"
        assert node_dict["city"] == "Test City"
        assert node_dict["latitude"] == 37.7749
        assert node_dict["longitude"] == -122.4194
        assert node_dict["is_tor_exit"] is False
        assert node_dict["seen_count"] == 1
        assert "first_seen" in node_dict
        assert "last_seen" in node_dict
        assert "organization_obj" in node_dict

    def test_network_node_repr(self, sample_network_node):
        """Test the NetworkNode.__repr__() method."""
        repr_str = repr(sample_network_node)
        assert "NetworkNode" in repr_str
        assert "192.168.1.1" in repr_str

    def test_network_node_organization_relationship(self, db_session, sample_network_node, sample_organization):
        """Test the relationship between NetworkNode and Organization."""
        db_session.refresh(sample_network_node)
        assert sample_network_node.organization_obj is not None
        assert sample_network_node.organization_obj.id == sample_organization.id
        assert sample_network_node in sample_organization.nodes

    def test_network_node_unique_ip(self, db_session, sample_organization):
        """Test that IP is the primary key and must be unique."""
        node1 = NetworkNode(ip="1.1.1.1", organization_id=sample_organization.id)
        db_session.add(node1)
        db_session.commit()

        node2 = NetworkNode(ip="1.1.1.1", organization_id=sample_organization.id)
        db_session.add(node2)
        
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()


class TestAnalysisSession:
    """Tests for the AnalysisSession model."""

    def test_analysis_session_creation(self, db_session, sample_network_node):
        """Test creating an analysis session."""
        session = AnalysisSession(
            target_ip=sample_network_node.ip,
            mode="Deep",
            timestamp=datetime.now(timezone.utc)
        )
        db_session.add(session)
        db_session.commit()
        
        assert session.id is not None
        assert session.target_ip == sample_network_node.ip
        assert session.mode == "Deep"
        assert session.timestamp is not None

    def test_analysis_session_dict(self, sample_analysis_session):
        """Test the AnalysisSession.dict() method."""
        session_dict = sample_analysis_session.dict()
        
        assert session_dict["id"] == sample_analysis_session.id
        assert session_dict["target_ip"] == "192.168.1.1"
        assert session_dict["mode"] == "Plain"
        assert "timestamp" in session_dict
        assert "hops" in session_dict

    def test_analysis_session_repr(self, sample_analysis_session):
        """Test the AnalysisSession.__repr__() method."""
        repr_str = repr(sample_analysis_session)
        assert "AnalysisSession" in repr_str
        assert str(sample_analysis_session.id) in repr_str


class TestPathHop:
    """Tests for the PathHop model."""

    def test_path_hop_creation(self, db_session, sample_analysis_session, sample_network_node):
        """Test creating a path hop."""
        hop = PathHop(
            session_id=sample_analysis_session.id,
            ip=sample_network_node.ip,
            hop_number=1,
            probe_index=1,
            rtt=0.010,
            timestamp=datetime.now(timezone.utc)
        )
        db_session.add(hop)
        db_session.commit()
        
        assert hop.id is not None
        assert hop.session_id == sample_analysis_session.id
        assert hop.hop_number == 1
        assert hop.rtt == 0.010

    def test_path_hop_dict(self, sample_path_hop):
        """Test the PathHop.dict() method."""
        hop_dict = sample_path_hop.dict()
        
        assert hop_dict["id"] == sample_path_hop.id
        assert hop_dict["session_id"] == sample_path_hop.session_id
        assert hop_dict["ip"] == "192.168.1.1"
        assert hop_dict["hop_number"] == 1
        assert hop_dict["probe_index"] == 1
        assert hop_dict["rtt"] == 0.005
        assert "timestamp" in hop_dict

    def test_path_hop_repr(self, sample_path_hop):
        """Test the PathHop.__repr__() method."""
        repr_str = repr(sample_path_hop)
        assert "PathHop" in repr_str

    def test_path_hop_session_relationship(self, db_session, sample_path_hop, sample_analysis_session):
        """Test the relationship between PathHop and AnalysisSession."""
        db_session.refresh(sample_path_hop)
        db_session.refresh(sample_analysis_session)
        
        assert sample_path_hop.session is not None
        assert sample_path_hop.session.id == sample_analysis_session.id
        assert sample_path_hop in sample_analysis_session.hops


class TestWebAccess:
    """Tests for the WebAccess model."""

    def test_web_access_creation(self, db_session, sample_network_node):
        """Test creating a web access record."""
        access = WebAccess(
            timestamp=datetime.now(timezone.utc),
            remote_addr=sample_network_node.ip,
            remote_port=12345,
            request="POST /api/data HTTP/1.1",
            method="POST",
            path="/api/data",
            status=201,
            body_bytes_sent=512,
            http_user_agent="Mozilla/5.0",
            raw={"key": "value"}
        )
        db_session.add(access)
        db_session.commit()
        
        assert access.id is not None
        assert access.remote_addr == sample_network_node.ip
        assert access.method == "POST"
        assert access.status == 201

    def test_web_access_dict(self, sample_web_access):
        """Test the WebAccess.dict() method."""
        access_dict = sample_web_access.dict()
        
        assert access_dict["id"] == sample_web_access.id
        assert access_dict["remote_addr"] == "192.168.1.1"
        assert access_dict["method"] == "GET"
        assert access_dict["path"] == "/test"
        assert access_dict["status"] == 200
        assert access_dict["http_user_agent"] == "TestAgent/1.0"
        assert "timestamp" in access_dict

    def test_web_access_node_relationship(self, db_session, sample_web_access, sample_network_node):
        """Test the relationship between WebAccess and NetworkNode."""
        db_session.refresh(sample_web_access)
        db_session.refresh(sample_network_node)
        
        assert sample_web_access.node is not None
        assert sample_web_access.node.ip == sample_network_node.ip
        assert sample_web_access in sample_network_node.web_accesses


class TestISP:
    """Tests for the ISP model."""

    def test_isp_creation(self, db_session):
        """Test creating an ISP."""
        isp = ISP(
            name="Test ISP",
            name_normalized="test isp",
            asn="AS12345",
            abuse_email="abuse@testisp.net",
            extra_data={}
        )
        db_session.add(isp)
        db_session.commit()
        
        assert isp.id is not None
        assert isp.name == "Test ISP"
        assert isp.name_normalized == "test isp"
        assert isp.asn == "AS12345"
        assert isp.abuse_email == "abuse@testisp.net"
        assert isp.created_at is not None

    def test_isp_dict(self, sample_isp):
        """Test the ISP.dict() method."""
        isp_dict = sample_isp.dict()
        
        assert isp_dict["id"] == sample_isp.id
        assert isp_dict["name"] == "Test ISP Provider"
        assert isp_dict["name_normalized"] == "test isp provider"
        assert isp_dict["asn"] == "AS12345"
        assert isp_dict["abuse_email"] == "abuse@testisp.net"
        assert "created_at" in isp_dict
        assert isp_dict["extra_data"] == {"note": "test isp"}

    def test_isp_repr(self, sample_isp):
        """Test the ISP.__repr__() method."""
        repr_str = repr(sample_isp)
        assert "ISP" in repr_str
        assert str(sample_isp.id) in repr_str
        assert "Test ISP Provider" in repr_str

    def test_isp_name_normalized_unique(self, db_session):
        """Test that name_normalized must be unique."""
        isp1 = ISP(name="ISP 1", name_normalized="same isp")
        db_session.add(isp1)
        db_session.commit()

        isp2 = ISP(name="ISP 2", name_normalized="same isp")
        db_session.add(isp2)
        
        with pytest.raises(Exception):  # IntegrityError
            db_session.commit()


class TestNetworkNodeWithISP:
    """Tests for NetworkNode with ISP relationship."""

    def test_network_node_with_isp_relationship(self, db_session, sample_isp):
        """Test the relationship between NetworkNode and ISP."""
        node = NetworkNode(
            ip="10.0.0.5",
            isp="Test ISP Provider",
            isp_id=sample_isp.id
        )
        db_session.add(node)
        db_session.commit()
        db_session.refresh(node)
        
        assert node.isp_obj is not None
        assert node.isp_obj.id == sample_isp.id
        assert node in sample_isp.nodes

    def test_network_node_dict_includes_isp(self, db_session, sample_isp):
        """Test that NetworkNode.dict() includes ISP information."""
        node = NetworkNode(
            ip="10.0.0.6",
            isp="Test ISP Provider",
            isp_id=sample_isp.id
        )
        db_session.add(node)
        db_session.commit()
        db_session.refresh(node)
        
        node_dict = node.dict()
        
        assert node_dict["isp"] == "Test ISP Provider"
        assert node_dict["isp_id"] == sample_isp.id
        assert node_dict["isp_obj"] is not None
        assert node_dict["isp_obj"]["name"] == "Test ISP Provider"


class TestOutgoingConnection:
    """Tests for the OutgoingConnection model."""

    def test_outgoing_connection_creation(self, db_session):
        """Test creating an outgoing connection."""
        conn = OutgoingConnection(
            local_addr="192.168.1.100",
            local_port=54321,
            remote_addr="8.8.8.8",
            remote_port=443,
            proto="tcp",
            status="ESTABLISHED",
            pid=1234,
            process_name="curl",
            direction="outgoing"
        )
        db_session.add(conn)
        db_session.commit()
        
        assert conn.id is not None
        assert conn.local_addr == "192.168.1.100"
        assert conn.local_port == 54321
        assert conn.remote_addr == "8.8.8.8"
        assert conn.remote_port == 443
        assert conn.proto == "tcp"
        assert conn.status == "ESTABLISHED"
        assert conn.pid == 1234
        assert conn.process_name == "curl"
        assert conn.direction == "outgoing"
        assert conn.timestamp is not None

    def test_outgoing_connection_dict(self, sample_outgoing_connection):
        """Test the OutgoingConnection.dict() method."""
        conn_dict = sample_outgoing_connection.dict()
        
        assert conn_dict["id"] == sample_outgoing_connection.id
        assert conn_dict["local_addr"] == "192.168.1.100"
        assert conn_dict["local_port"] == 54321
        assert conn_dict["remote_addr"] == "8.8.8.8"
        assert conn_dict["remote_port"] == 443
        assert conn_dict["proto"] == "tcp"
        assert conn_dict["status"] == "ESTABLISHED"
        assert conn_dict["pid"] == 1234
        assert conn_dict["process_name"] == "python3"
        assert conn_dict["direction"] == "outgoing"
        assert "timestamp" in conn_dict

    def test_outgoing_connection_repr(self, sample_outgoing_connection):
        """Test the OutgoingConnection.__repr__() method."""
        repr_str = repr(sample_outgoing_connection)
        assert "OutgoingConnection" in repr_str
        assert "192.168.1.100" in repr_str
        assert "8.8.8.8" in repr_str

    def test_outgoing_connection_internal_direction(self, db_session):
        """Test creating an internal connection."""
        conn = OutgoingConnection(
            local_addr="192.168.1.100",
            local_port=54321,
            remote_addr="192.168.1.1",
            remote_port=80,
            proto="tcp",
            direction="internal"
        )
        db_session.add(conn)
        db_session.commit()
        
        assert conn.direction == "internal"

    def test_outgoing_connection_nullable_fields(self, db_session):
        """Test that optional fields can be null."""
        conn = OutgoingConnection(
            remote_addr="8.8.8.8",
            remote_port=443,
            proto="tcp"
        )
        db_session.add(conn)
        db_session.commit()
        
        assert conn.local_addr is None
        assert conn.local_port is None
        assert conn.pid is None
        assert conn.process_name is None
